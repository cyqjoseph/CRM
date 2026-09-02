import json
from unittest.mock import MagicMock, patch

from conftest import load_module

app = load_module("api_audit_app", "functions/api_audit/app.py")


def _event(entity_id, claims):
    return {
        "resource": "/audit",
        "pathParameters": None,
        "queryStringParameters": {"entityId": entity_id},
        "requestContext": {"authorizer": {"claims": claims}},
    }


@patch("boto3.resource")
def test_non_admin_cannot_query_another_owners_entity(mock_resource):
    response = app.handler(_event("someone-elses-entity", {"sub": "owner-1"}), None)
    assert response["statusCode"] == 403
    mock_resource.return_value.Table.return_value.query.assert_not_called()


@patch("boto3.resource")
def test_non_admin_can_query_their_own_entity(mock_resource):
    table = MagicMock()
    table.query.return_value = {"Items": []}
    mock_resource.return_value.Table.return_value = table

    response = app.handler(_event("owner-1", {"sub": "owner-1"}), None)
    assert response["statusCode"] == 200
    assert table.query.called


@patch("boto3.resource")
def test_admin_can_query_any_entity(mock_resource):
    table = MagicMock()
    table.query.return_value = {"Items": []}
    mock_resource.return_value.Table.return_value = table

    claims = {"sub": "owner-1", "cognito:groups": "admins"}
    response = app.handler(_event("someone-elses-entity", claims), None)
    assert response["statusCode"] == 200
    assert table.query.called


def _execution_event(execution_id, claims):
    return {
        "resource": "/executions/{executionId}",
        "pathParameters": {"executionId": execution_id},
        "queryStringParameters": None,
        "requestContext": {"authorizer": {"claims": claims}},
    }


@patch("boto3.resource")
@patch("boto3.client")
def test_get_execution_returns_status_and_output(mock_client, mock_resource):
    sfn = MagicMock()
    sfn.describe_execution.return_value = {"status": "SUCCEEDED", "output": '{"ok": true}'}
    sfn.get_execution_history.return_value = {"events": []}
    mock_client.return_value = sfn

    response = app.handler(
        _execution_event("arn:aws:states:renewal:exec-1", {"sub": "owner-1"}), None
    )

    assert response["statusCode"] == 200
    body = json.loads(response["body"])
    assert body["status"] == "SUCCEEDED"
    sfn.get_execution_history.assert_called_once()


@patch("boto3.resource")
@patch("boto3.client")
def test_get_execution_returns_500_with_details_on_failure(mock_client, mock_resource):
    sfn = MagicMock()
    sfn.describe_execution.side_effect = Exception("AccessDeniedException: not authorized")
    mock_client.return_value = sfn

    response = app.handler(
        _execution_event("arn:aws:states:renewal:exec-1", {"sub": "owner-1"}), None
    )

    assert response["statusCode"] == 500
    body = json.loads(response["body"])
    assert body["error"] == "DescribeExecution call failed"
    assert "not authorized" in body["details"]


# --- Percent-encoded execution ARNs ------------------------------------------
# An execution ARN is full of colons, so the browser must percent-encode it into
# the path. API Gateway REST APIs then hand it to Lambda STILL ENCODED, and
# DescribeExecution rejects it with
#   InvalidArn: Invalid ARN prefix: arn%3Aaws%3Astates%3A...
# which reads like the caller sent a bad ARN rather than an un-decoded one. This
# broke every renew/rotate status poll in the browser while working fine from
# curl with an unencoded ARN.

ENCODED_ARN = (
    "arn%3Aaws%3Astates%3Aap-southeast-1%3A544635841962%3Aexecution%3A"
    "app-d9fae51c-1929cc69-renewal-sfn%3Ad29130d9-fefd-4ee2-9387-d07c33b9d02a"
)
DECODED_ARN = (
    "arn:aws:states:ap-southeast-1:544635841962:execution:"
    "app-d9fae51c-1929cc69-renewal-sfn:d29130d9-fefd-4ee2-9387-d07c33b9d02a"
)


@patch("boto3.resource")
@patch("boto3.client")
def test_a_percent_encoded_execution_arn_is_decoded_before_the_aws_call(mock_client, mock_resource):
    sfn = MagicMock()
    sfn.describe_execution.return_value = {"status": "SUCCEEDED", "output": "{}"}
    sfn.get_execution_history.return_value = {"events": []}
    mock_client.return_value = sfn

    response = app.handler(_execution_event(ENCODED_ARN, {"sub": "owner-1"}), None)

    assert response["statusCode"] == 200
    sfn.describe_execution.assert_called_once_with(executionArn=DECODED_ARN)


@patch("boto3.resource")
@patch("boto3.client")
def test_an_already_decoded_arn_is_passed_through_unchanged(mock_client, mock_resource):
    """Decoding must be idempotent — a well-formed ARN contains no '%', so it
    must survive unquote() untouched whichever way API Gateway behaves."""
    sfn = MagicMock()
    sfn.describe_execution.return_value = {"status": "RUNNING"}
    mock_client.return_value = sfn

    response = app.handler(_execution_event(DECODED_ARN, {"sub": "owner-1"}), None)

    assert response["statusCode"] == 200
    sfn.describe_execution.assert_called_once_with(executionArn=DECODED_ARN)


@patch("boto3.resource")
@patch("boto3.client")
def test_a_malformed_arn_is_a_400_not_a_500(mock_client, mock_resource):
    """Bad caller input is not a server error, and botocore's ParamValidationError
    is far less legible than saying what was expected."""
    sfn = MagicMock()
    mock_client.return_value = sfn

    response = app.handler(_execution_event("not-an-arn", {"sub": "owner-1"}), None)

    assert response["statusCode"] == 400
    body = json.loads(response["body"])
    assert "execution ARN" in body["error"]
    sfn.describe_execution.assert_not_called()


@patch("boto3.resource")
@patch("boto3.client")
def test_a_missing_execution_id_is_a_400_not_a_500(mock_client, mock_resource):
    sfn = MagicMock()
    mock_client.return_value = sfn

    event = _execution_event("ignored", {"sub": "owner-1"})
    event["pathParameters"] = {}

    response = app.handler(event, None)

    assert response["statusCode"] == 400
    sfn.describe_execution.assert_not_called()


# --- Shared team visibility --------------------------------------------------
#
# Renewal and rotation events hang off a CertId/AccountIdHash, not off the
# clicker's sub. Scoping non-admins to their own actor id alone meant the
# "check the audit tab for details" the UI prints after a failed renewal was
# advice only an admin could act on.

from crm_common import SHARED_OWNER_ID  # noqa: E402


def _tables(cert_item=None, iam_item=None, audit_items=None):
    """Route boto3.resource().Table(name) to a per-table stub."""
    audit = MagicMock()
    audit.query.return_value = {"Items": audit_items or []}
    certs = MagicMock()
    certs.get_item.return_value = {"Item": cert_item} if cert_item else {}
    iam = MagicMock()
    iam.get_item.return_value = {"Item": iam_item} if iam_item else {}

    def table_for(name):
        if name == app.CERT_TABLE_NAME:
            return certs
        if name == app.IAM_TABLE_NAME:
            return iam
        return audit

    resource = MagicMock()
    resource.Table.side_effect = table_for
    return resource, audit


@patch("boto3.resource")
def test_any_login_can_read_the_shared_partitions_trail(mock_resource):
    resource, audit = _tables()
    mock_resource.return_value = resource

    response = app.handler(_event(SHARED_OWNER_ID, {"sub": "sub-b"}), None)

    assert response["statusCode"] == 200
    assert audit.query.called


@patch("boto3.resource")
def test_any_login_can_read_the_trail_of_a_shared_certificate(mock_resource):
    resource, audit = _tables(cert_item={"CertId": "ec2-aaa", "OwnerId": SHARED_OWNER_ID})
    mock_resource.return_value = resource

    response = app.handler(_event("ec2-aaa", {"sub": "sub-b"}), None)

    assert response["statusCode"] == 200
    assert audit.query.called


@patch("boto3.resource")
def test_any_login_can_read_the_trail_of_a_shared_account(mock_resource):
    resource, audit = _tables(iam_item={"AccountIdHash": "demo-acct-1", "OwnerId": SHARED_OWNER_ID})
    mock_resource.return_value = resource

    response = app.handler(_event("demo-acct-1", {"sub": "sub-b"}), None)

    assert response["statusCode"] == 200
    assert audit.query.called


@patch("boto3.resource")
def test_the_trail_of_a_cert_owned_by_another_login_is_still_forbidden(mock_resource):
    resource, audit = _tables(cert_item={"CertId": "theirs", "OwnerId": "sub-c"})
    mock_resource.return_value = resource

    response = app.handler(_event("theirs", {"sub": "sub-b"}), None)

    assert response["statusCode"] == 403
    audit.query.assert_not_called()


@patch("boto3.resource")
def test_a_failing_inventory_lookup_falls_back_to_forbidden_rather_than_500(mock_resource):
    resource, audit = _tables()
    resource.Table.side_effect = None
    failing = MagicMock()
    failing.get_item.side_effect = Exception("AccessDeniedException")
    failing.query.return_value = {"Items": []}
    resource.Table.return_value = failing
    mock_resource.return_value = resource

    response = app.handler(_event("unknown-entity", {"sub": "sub-b"}), None)

    assert response["statusCode"] == 403
