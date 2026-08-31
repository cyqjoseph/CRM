import json
from unittest.mock import MagicMock, patch

from conftest import load_module

app = load_module("password_reset_approver_app", "functions/password_reset_approver/app.py")


def _event(method, request_id, action, claims=None):
    return {
        "httpMethod": method,
        "resource": f"/password-resets/{{requestId}}/{action}",
        "pathParameters": {"requestId": request_id},
        "queryStringParameters": None,
        "requestContext": {"authorizer": {"claims": claims or {"sub": "admin-1", "cognito:groups": "admins"}}},
        "body": None,
    }


@patch("boto3.client")
@patch("boto3.resource")
def test_approve_requires_admin(mock_resource, mock_client):
    table = MagicMock()
    mock_resource.return_value.Table.return_value = table

    response = app.handler(_event("POST", "r1", "approve", claims={"sub": "owner-1"}), None)

    assert response["statusCode"] == 403
    table.query.assert_not_called()


@patch("boto3.client")
@patch("boto3.resource")
def test_approve_starts_the_reset_state_machine_and_marks_approved(mock_resource, mock_client):
    table = MagicMock()
    table.query.return_value = {
        "Items": [{"RequestId": "r1", "Timestamp": "2026-01-01T00:00:00+00:00", "AccountId": "hash-1", "Status": "pending"}]
    }
    mock_resource.return_value.Table.return_value = table

    sfn = MagicMock()
    sfn.start_execution.return_value = {"executionArn": "arn:aws:states:reset:exec-1"}
    mock_client.return_value = sfn

    response = app.handler(_event("POST", "r1", "approve"), None)

    assert response["statusCode"] == 202
    body = json.loads(response["body"])
    assert body["executionArn"] == "arn:aws:states:reset:exec-1"

    update_kwargs = table.update_item.call_args.kwargs
    assert update_kwargs["Key"] == {"RequestId": "r1", "Timestamp": "2026-01-01T00:00:00+00:00"}
    assert update_kwargs["ExpressionAttributeValues"][":status"] == "approved"

    start_kwargs = sfn.start_execution.call_args.kwargs
    payload = json.loads(start_kwargs["input"])
    assert payload["requestId"] == "r1"
    assert payload["accountId"] == "hash-1"


@patch("boto3.client")
@patch("boto3.resource")
def test_approve_on_a_non_pending_request_is_a_conflict(mock_resource, mock_client):
    table = MagicMock()
    table.query.return_value = {
        "Items": [{"RequestId": "r1", "Timestamp": "2026-01-01T00:00:00+00:00", "AccountId": "hash-1", "Status": "rejected"}]
    }
    mock_resource.return_value.Table.return_value = table
    sfn = MagicMock()
    mock_client.return_value = sfn

    response = app.handler(_event("POST", "r1", "approve"), None)

    assert response["statusCode"] == 409
    sfn.start_execution.assert_not_called()


@patch("boto3.client")
@patch("boto3.resource")
def test_reject_marks_rejected_and_notifies_without_starting_a_workflow(mock_resource, mock_client):
    table = MagicMock()
    table.query.return_value = {
        "Items": [{"RequestId": "r1", "Timestamp": "2026-01-01T00:00:00+00:00", "AccountId": "hash-1", "Status": "pending"}]
    }
    mock_resource.return_value.Table.return_value = table
    sns = MagicMock()
    mock_client.return_value = sns

    response = app.handler(_event("POST", "r1", "reject"), None)

    assert response["statusCode"] == 200
    update_kwargs = table.update_item.call_args.kwargs
    assert update_kwargs["ExpressionAttributeValues"][":status"] == "rejected"
    sns.publish.assert_called_once()
    sns.start_execution.assert_not_called() if hasattr(sns, "start_execution") else None


@patch("boto3.client")
@patch("boto3.resource")
def test_approve_missing_request_is_404(mock_resource, mock_client):
    table = MagicMock()
    table.query.return_value = {"Items": []}
    mock_resource.return_value.Table.return_value = table

    response = app.handler(_event("POST", "does-not-exist", "approve"), None)

    assert response["statusCode"] == 404
