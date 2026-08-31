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
