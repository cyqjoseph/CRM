import json
from unittest.mock import MagicMock, patch

from conftest import load_module

app = load_module("api_iam_app", "functions/api_iam/app.py")


def _event(method, account_id=None, resource="/iam/accounts", claims=None):
    path_params = {"accountId": account_id} if account_id else None
    return {
        "httpMethod": method,
        "resource": resource,
        "pathParameters": path_params,
        "queryStringParameters": None,
        "requestContext": {"authorizer": {"claims": claims or {"sub": "owner-1"}}},
    }


@patch("boto3.resource")
@patch("boto3.client")
def test_rotate_returns_202_with_execution_arn(mock_client, mock_resource):
    table = MagicMock()
    table.get_item.return_value = {"Item": {"AccountIdHash": "hash-1", "OwnerId": "owner-1"}}
    mock_resource.return_value.Table.return_value = table

    sfn = MagicMock()
    sfn.start_execution.return_value = {"executionArn": "arn:aws:states:rotation:exec-1"}
    mock_client.return_value = sfn

    response = app.handler(
        _event("POST", account_id="hash-1", resource="/iam/accounts/{accountId}/rotate"), None
    )

    assert response["statusCode"] == 202
    body = json.loads(response["body"])
    assert "executionArn" in body
    assert body["executionArn"] == "arn:aws:states:rotation:exec-1"


@patch("boto3.resource")
@patch("boto3.client")
def test_list_without_a_sub_claim_is_401_not_a_dynamodb_error(mock_client, mock_resource):
    """Same empty-partition-key trap as GET /certs — see test_api_certs.py."""
    table = MagicMock()
    mock_resource.return_value.Table.return_value = table

    # Truthy, so _event does not substitute its default — but no `sub`.
    response = app.handler(_event("GET", claims={"email": "nobody@example.com"}), None)

    assert response["statusCode"] == 401
    table.query.assert_not_called()


@patch("boto3.resource")
@patch("boto3.client")
def test_list_filters_by_status_query_param(mock_client, mock_resource):
    table = MagicMock()
    table.query.return_value = {
        "Items": [
            {"AccountIdHash": "hash-1", "OwnerId": "owner-1", "Status": "warning"},
            {"AccountIdHash": "hash-2", "OwnerId": "owner-1", "Status": "active"},
        ]
    }
    mock_resource.return_value.Table.return_value = table

    event = _event("GET")
    event["queryStringParameters"] = {"status": "warning"}
    response = app.handler(event, None)

    body = json.loads(response["body"])
    assert [item["AccountIdHash"] for item in body["items"]] == ["hash-1"]


# --- Shared team visibility --------------------------------------------------
# Same root cause as api-certs-fn: OwnerIndex keyed on the caller's Cognito sub
# meant one login per row.

from crm_common import SHARED_OWNER_ID  # noqa: E402


def _partitioned_table(rows_by_owner):
    table = MagicMock()
    table.query.side_effect = lambda **kwargs: {
        "Items": rows_by_owner.get(kwargs["ExpressionAttributeValues"][":owner"], [])
    }
    return table


def _account(account_id, owner_id, rotation="2027-01-01"):
    return {
        "AccountIdHash": account_id,
        "OwnerId": owner_id,
        "NextRotationDate": rotation,
        "Status": "active",
        "UserName": f"svc-{account_id}",
    }


@patch("boto3.resource")
@patch("boto3.client")
def test_two_different_logins_see_the_same_shared_accounts(mock_client, mock_resource):
    shared = [_account("demo-acct-1", SHARED_OWNER_ID), _account("demo-acct-2", SHARED_OWNER_ID)]
    table = _partitioned_table({SHARED_OWNER_ID: shared})
    mock_resource.return_value.Table.return_value = table

    first = app.handler(_event("GET", claims={"sub": "sub-a"}), None)
    second = app.handler(_event("GET", claims={"sub": "sub-b"}), None)

    ids_a = {a["AccountIdHash"] for a in json.loads(first["body"])["items"]}
    ids_b = {a["AccountIdHash"] for a in json.loads(second["body"])["items"]}
    assert ids_a == ids_b == {"demo-acct-1", "demo-acct-2"}


@patch("boto3.resource")
@patch("boto3.client")
def test_accounts_are_ordered_by_soonest_rotation(mock_client, mock_resource):
    table = _partitioned_table({
        SHARED_OWNER_ID: [
            _account("later", SHARED_OWNER_ID, rotation="2027-06-01"),
            _account("sooner", SHARED_OWNER_ID, rotation="2026-09-10"),
        ],
    })
    mock_resource.return_value.Table.return_value = table

    response = app.handler(_event("GET", claims={"sub": "sub-a"}), None)

    assert [a["AccountIdHash"] for a in json.loads(response["body"])["items"]] == ["sooner", "later"]


@patch("boto3.resource")
@patch("boto3.client")
def test_any_login_can_rotate_a_shared_account(mock_client, mock_resource):
    table = MagicMock()
    table.get_item.return_value = {"Item": _account("demo-acct-1", SHARED_OWNER_ID)}
    mock_resource.return_value.Table.return_value = table

    sfn = MagicMock()
    sfn.start_execution.return_value = {"executionArn": "arn:aws:states:rotation:exec-9"}
    mock_client.return_value = sfn

    response = app.handler(
        _event("POST", account_id="demo-acct-1", resource="/iam/accounts/{accountId}/rotate",
               claims={"sub": "sub-b"}),
        None,
    )

    assert response["statusCode"] == 202


@patch("boto3.resource")
@patch("boto3.client")
def test_an_account_owned_by_another_login_is_still_not_rotatable(mock_client, mock_resource):
    table = MagicMock()
    table.get_item.return_value = {"Item": _account("theirs", "sub-c")}
    mock_resource.return_value.Table.return_value = table

    response = app.handler(
        _event("POST", account_id="theirs", resource="/iam/accounts/{accountId}/rotate",
               claims={"sub": "sub-b"}),
        None,
    )

    assert response["statusCode"] == 404
    mock_client.return_value.start_execution.assert_not_called()
