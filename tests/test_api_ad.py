import json
from unittest.mock import MagicMock, patch

from conftest import load_module

app = load_module("api_ad_app", "functions/api_ad/app.py")


def _event(method, account_id=None, resource="/ad-accounts", claims=None):
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
        _event("POST", account_id="hash-1", resource="/ad-accounts/{accountId}/rotate"), None
    )

    assert response["statusCode"] == 202
    body = json.loads(response["body"])
    assert "executionArn" in body
    assert body["executionArn"] == "arn:aws:states:rotation:exec-1"
