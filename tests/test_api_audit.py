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
