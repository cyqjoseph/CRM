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
def test_renew_of_other_owners_cert_is_not_found(mock_client, mock_resource):
    table = MagicMock()
    table.get_item.return_value = {"Item": {"CertId": "cert-1", "OwnerId": "someone-else"}}
    mock_resource.return_value.Table.return_value = table

    response = app.handler(
        _event("POST", cert_id="cert-1", resource="/certs/{certId}/renew"), None
    )

    assert response["statusCode"] == 404
    mock_client.return_value.start_execution.assert_not_called()
