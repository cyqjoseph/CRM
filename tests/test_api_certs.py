import json
from unittest.mock import MagicMock, patch

from conftest import load_module

app = load_module("api_certs_app", "functions/api_certs/app.py")


def _event(method, cert_id=None, resource="/certs", claims=None):
    path_params = {"certId": cert_id} if cert_id else None
    return {
        "httpMethod": method,
        "resource": resource,
        "pathParameters": path_params,
        "queryStringParameters": None,
        "requestContext": {"authorizer": {"claims": claims or {"sub": "owner-1"}}},
    }


@patch("boto3.resource")
@patch("boto3.client")
def test_renew_returns_202_with_execution_arn(mock_client, mock_resource):
    table = MagicMock()
    table.get_item.return_value = {"Item": {"CertId": "cert-1", "OwnerId": "owner-1"}}
    mock_resource.return_value.Table.return_value = table

    sfn = MagicMock()
    sfn.start_execution.return_value = {"executionArn": "arn:aws:states:renewal:exec-1"}
    mock_client.return_value = sfn

    response = app.handler(
        _event("POST", cert_id="cert-1", resource="/certs/{certId}/renew"), None
    )

    assert response["statusCode"] == 202
    body = json.loads(response["body"])
    assert "executionArn" in body
    assert body["executionArn"] == "arn:aws:states:renewal:exec-1"


@patch("boto3.resource")
@patch("boto3.client")
def test_list_without_a_sub_claim_is_401_not_a_dynamodb_error(mock_client, mock_resource):
    """An empty partition-key value is a ValidationException, i.e. another 502.

    DynamoDB rejects an empty string for a key attribute, so querying OwnerIndex
    with an absent `sub` raises instead of returning an empty list. Reject it
    before the call so the caller gets a readable 401.
    """
    table = MagicMock()
    mock_resource.return_value.Table.return_value = table

    # Truthy, so _event does not substitute its default — but no `sub`.
    response = app.handler(_event("GET", claims={"email": "nobody@example.com"}), None)

    assert response["statusCode"] == 401
    table.query.assert_not_called()


@patch("boto3.resource")
@patch("boto3.client")
def test_renew_returns_500_with_details_when_start_execution_fails(mock_client, mock_resource):
    table = MagicMock()
    table.get_item.return_value = {"Item": {"CertId": "cert-1", "OwnerId": "owner-1"}}
    mock_resource.return_value.Table.return_value = table

    sfn = MagicMock()
    sfn.start_execution.side_effect = Exception("AccessDeniedException: not authorized")
    mock_client.return_value = sfn

    response = app.handler(
        _event("POST", cert_id="cert-1", resource="/certs/{certId}/renew"), None
    )

    assert response["statusCode"] == 500
    body = json.loads(response["body"])
    assert body["error"] == "Step Functions call failed"
    assert "not authorized" in body["details"]
    assert body["certId"] == "cert-1"


@patch("boto3.resource")
@patch("boto3.client")
def test_renew_of_other_owners_cert_is_not_found(mock_client, mock_resource):
    table = MagicMock()
    table.get_item.return_value = {"Item": {"CertId": "cert-1", "OwnerId": "someone-else"}}
    mock_resource.return_value.Table.return_value = table

    response = app.handler(
        _event("POST", cert_id="cert-1", resource="/certs/{certId}/renew"), None
    )

    assert response["statusCode"] == 404
    mock_client.return_value.start_execution.assert_not_called()


# --- Shared team visibility --------------------------------------------------
#
# The bug these cover: OwnerId is OwnerIndex's HASH key, so querying it with the
# caller's Cognito `sub` alone made every row belong to exactly one login. Three
# team members sharing the same certificates saw three different dashboards, and
# the rows ec2-discovery-fn wrote (owned by the shared scanner identity) showed
# up for nobody at all.

from crm_common import SHARED_OWNER_ID  # noqa: E402


def _partitioned_table(rows_by_owner):
    """A table whose OwnerIndex query answers per requested OwnerId."""
    table = MagicMock()
    table.query.side_effect = lambda **kwargs: {
        "Items": rows_by_owner.get(kwargs["ExpressionAttributeValues"][":owner"], [])
    }
    return table


def _cert(cert_id, owner_id, expiry="2027-01-01"):
    return {"CertId": cert_id, "OwnerId": owner_id, "ExpiryDate": expiry, "Status": "ISSUED"}


@patch("boto3.resource")
@patch("boto3.client")
def test_two_different_logins_see_the_same_shared_inventory(mock_client, mock_resource):
    shared = [_cert("ec2-aaa", SHARED_OWNER_ID), _cert("demo-cert-0001", SHARED_OWNER_ID)]
    table = _partitioned_table({SHARED_OWNER_ID: shared})
    mock_resource.return_value.Table.return_value = table

    first = app.handler(_event("GET", claims={"sub": "sub-a"}), None)
    second = app.handler(_event("GET", claims={"sub": "sub-b"}), None)

    assert first["statusCode"] == second["statusCode"] == 200
    ids_a = {c["CertId"] for c in json.loads(first["body"])["items"]}
    ids_b = {c["CertId"] for c in json.loads(second["body"])["items"]}
    assert ids_a == ids_b == {"ec2-aaa", "demo-cert-0001"}


@patch("boto3.resource")
@patch("boto3.client")
def test_the_shared_partition_is_queried_for_every_caller(mock_resource_client, mock_resource):
    table = _partitioned_table({})
    mock_resource.return_value.Table.return_value = table

    app.handler(_event("GET", claims={"sub": "sub-a"}), None)

    queried = [c.kwargs["ExpressionAttributeValues"][":owner"] for c in table.query.call_args_list]
    assert SHARED_OWNER_ID in queried


@patch("boto3.resource")
@patch("boto3.client")
def test_rows_still_owned_by_the_callers_own_sub_are_included(mock_client, mock_resource):
    """Rows seeded per-login before the move to a shared partition must not
    disappear from that login's dashboard."""
    table = _partitioned_table({
        SHARED_OWNER_ID: [_cert("shared-1", SHARED_OWNER_ID)],
        "sub-a": [_cert("legacy-1", "sub-a")],
    })
    mock_resource.return_value.Table.return_value = table

    response = app.handler(_event("GET", claims={"sub": "sub-a"}), None)

    ids = {c["CertId"] for c in json.loads(response["body"])["items"]}
    assert ids == {"shared-1", "legacy-1"}


@patch("boto3.resource")
@patch("boto3.client")
def test_a_row_present_in_both_partitions_is_listed_once(mock_client, mock_resource):
    table = _partitioned_table({
        SHARED_OWNER_ID: [_cert("demo-cert-0001", SHARED_OWNER_ID)],
        "sub-a": [_cert("demo-cert-0001", "sub-a")],
    })
    mock_resource.return_value.Table.return_value = table

    response = app.handler(_event("GET", claims={"sub": "sub-a"}), None)

    items = json.loads(response["body"])["items"]
    assert [i["CertId"] for i in items] == ["demo-cert-0001"]


@patch("boto3.resource")
@patch("boto3.client")
def test_results_are_ordered_by_soonest_expiry(mock_client, mock_resource):
    """Merging partitions loses a single partition's ExpiryDate ordering, and
    what expires next is the dashboard's whole point."""
    table = _partitioned_table({
        SHARED_OWNER_ID: [
            _cert("later", SHARED_OWNER_ID, expiry="2027-06-01"),
            _cert("sooner", SHARED_OWNER_ID, expiry="2026-09-05"),
        ],
    })
    mock_resource.return_value.Table.return_value = table

    response = app.handler(_event("GET", claims={"sub": "sub-a"}), None)

    assert [i["CertId"] for i in json.loads(response["body"])["items"]] == ["sooner", "later"]


@patch("boto3.resource")
@patch("boto3.client")
def test_any_login_can_renew_a_shared_cert(mock_client, mock_resource):
    """A shared asset the whole team can see is one the whole team can act on —
    otherwise every Renew button but the seeding login's returns 404."""
    table = MagicMock()
    table.get_item.return_value = {"Item": _cert("ec2-aaa", SHARED_OWNER_ID)}
    mock_resource.return_value.Table.return_value = table

    sfn = MagicMock()
    sfn.start_execution.return_value = {"executionArn": "arn:aws:states:renewal:exec-9"}
    mock_client.return_value = sfn

    response = app.handler(
        _event("POST", cert_id="ec2-aaa", resource="/certs/{certId}/renew", claims={"sub": "sub-b"}),
        None,
    )

    assert response["statusCode"] == 202


@patch("boto3.resource")
@patch("boto3.client")
def test_get_a_shared_cert_is_visible_to_any_login(mock_client, mock_resource):
    table = MagicMock()
    table.get_item.return_value = {"Item": _cert("ec2-aaa", SHARED_OWNER_ID)}
    mock_resource.return_value.Table.return_value = table

    response = app.handler(_event("GET", cert_id="ec2-aaa", claims={"sub": "sub-b"}), None)

    assert response["statusCode"] == 200


@patch("boto3.resource")
@patch("boto3.client")
def test_an_admin_can_still_scope_the_list_to_one_owner(mock_client, mock_resource):
    table = _partitioned_table({"someone-else": [_cert("theirs", "someone-else")]})
    mock_resource.return_value.Table.return_value = table

    event = _event("GET", claims={"sub": "sub-a", "cognito:groups": "admins"})
    event["queryStringParameters"] = {"ownerId": "someone-else"}
    response = app.handler(event, None)

    items = json.loads(response["body"])["items"]
    assert [i["CertId"] for i in items] == ["theirs"]
    queried = [c.kwargs["ExpressionAttributeValues"][":owner"] for c in table.query.call_args_list]
    assert queried == ["someone-else"], "an explicit owner scope must not also pull the shared partition"


@patch("boto3.resource")
@patch("boto3.client")
def test_a_non_admin_cannot_scope_the_list_to_another_owner(mock_client, mock_resource):
    table = _partitioned_table({"someone-else": [_cert("theirs", "someone-else")]})
    mock_resource.return_value.Table.return_value = table

    event = _event("GET", claims={"sub": "sub-a"})
    event["queryStringParameters"] = {"ownerId": "someone-else"}
    app.handler(event, None)

    queried = [c.kwargs["ExpressionAttributeValues"][":owner"] for c in table.query.call_args_list]
    assert "someone-else" not in queried
