import json
from unittest.mock import MagicMock, patch

from conftest import load_module

app = load_module("api_password_resets_app", "functions/api_password_resets/app.py")


def _event(method, resource="/password-resets", body=None, query=None, claims=None):
    return {
        "httpMethod": method,
        "resource": resource,
        "pathParameters": None,
        "queryStringParameters": query,
        "requestContext": {"authorizer": {"claims": claims or {"sub": "owner-1"}}},
        "body": json.dumps(body) if body is not None else None,
    }


@patch("boto3.resource")
def test_create_request_rejects_account_the_caller_does_not_own(mock_resource):
    iam_table = MagicMock()
    iam_table.get_item.return_value = {"Item": {"AccountIdHash": "hash-1", "OwnerId": "someone-else"}}
    requests_table = MagicMock()

    def table_side_effect(name):
        return iam_table if name == app.IAM_TABLE_NAME else requests_table

    mock_resource.return_value.Table.side_effect = table_side_effect

    response = app.handler(
        _event("POST", body={"accountId": "hash-1", "reason": "locked out"}), None
    )

    assert response["statusCode"] == 404
    requests_table.put_item.assert_not_called()


@patch("boto3.resource")
def test_create_request_stores_pending_request_for_owned_account(mock_resource):
    iam_table = MagicMock()
    iam_table.get_item.return_value = {"Item": {"AccountIdHash": "hash-1", "OwnerId": "owner-1"}}
    requests_table = MagicMock()

    def table_side_effect(name):
        return iam_table if name == app.IAM_TABLE_NAME else requests_table

    mock_resource.return_value.Table.side_effect = table_side_effect

    response = app.handler(
        _event("POST", body={"accountId": "hash-1", "reason": "locked out"}), None
    )

    assert response["statusCode"] == 201
    body = json.loads(response["body"])
    assert body["Status"] == "pending"
    assert body["AccountId"] == "hash-1"
    assert body["RequestedBy"] == "owner-1"
    assert "RequestId" in body and "Timestamp" in body

    # AUDIT_TABLE_NAME also falls into the mock's "else" branch, so the audit
    # write and the request write land on the same mock table — find the
    # request-creation call specifically rather than assuming it's the last one.
    request_calls = [
        call for call in requests_table.put_item.call_args_list if "Status" in call.kwargs["Item"]
    ]
    assert len(request_calls) == 1
    assert request_calls[0].kwargs["Item"]["Status"] == "pending"


@patch("boto3.resource")
def test_create_request_without_a_sub_claim_is_401(mock_resource):
    requests_table = MagicMock()
    mock_resource.return_value.Table.return_value = requests_table

    response = app.handler(
        _event("POST", body={"accountId": "hash-1"}, claims={"email": "nobody@example.com"}), None
    )

    assert response["statusCode"] == 401
    requests_table.put_item.assert_not_called()


@patch("boto3.resource")
def test_list_requires_admin(mock_resource):
    table = MagicMock()
    mock_resource.return_value.Table.return_value = table

    response = app.handler(_event("GET"), None)

    assert response["statusCode"] == 403
    table.scan.assert_not_called()
    table.query.assert_not_called()


@patch("boto3.resource")
def test_list_as_admin_filters_by_status_via_the_status_index(mock_resource):
    table = MagicMock()
    table.query.return_value = {"Items": [{"RequestId": "r1", "Status": "pending"}]}
    mock_resource.return_value.Table.return_value = table

    response = app.handler(
        _event("GET", query={"status": "pending"}, claims={"sub": "admin-1", "cognito:groups": "admins"})
    , None)

    assert response["statusCode"] == 200
    body = json.loads(response["body"])
    assert body["items"] == [{"RequestId": "r1", "Status": "pending"}]
    kwargs = table.query.call_args.kwargs
    assert kwargs["IndexName"] == "StatusIndex"


@patch("boto3.resource")
def test_list_as_admin_without_status_scans(mock_resource):
    table = MagicMock()
    table.scan.return_value = {"Items": [{"RequestId": "r1", "Status": "pending"}]}
    mock_resource.return_value.Table.return_value = table

    response = app.handler(
        _event("GET", claims={"sub": "admin-1", "cognito:groups": "admins"}), None
    )

    assert response["statusCode"] == 200
    table.scan.assert_called_once()
