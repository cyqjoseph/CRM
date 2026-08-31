import json
from unittest.mock import MagicMock, patch

from conftest import load_module

app = load_module("sync_on_prem_app", "functions/sync_on_prem/app.py")


def _event(body):
    return {
        "httpMethod": "POST",
        "resource": "/sync/on-prem-data",
        "body": json.dumps(body) if body is not None else None,
    }


@patch("boto3.resource")
def test_valid_payload_is_written_to_the_named_table(mock_resource):
    table = MagicMock()
    mock_resource.return_value.Table.return_value = table

    response = app.handler(_event({"table": "certificates", "item": {"CertId": "onprem-1"}}), None)

    assert response["statusCode"] == 202
    table.put_item.assert_called_once_with(Item={"CertId": "onprem-1"})
    mock_resource.return_value.Table.assert_called_once_with(app.CERT_TABLE_NAME)


@patch("boto3.resource")
def test_unknown_table_key_is_rejected(mock_resource):
    response = app.handler(_event({"table": "not-a-real-table", "item": {}}), None)

    assert response["statusCode"] == 400
    mock_resource.return_value.Table.return_value.put_item.assert_not_called()


@patch("boto3.resource")
def test_missing_item_is_rejected(mock_resource):
    response = app.handler(_event({"table": "iam-accounts"}), None)

    assert response["statusCode"] == 400


@patch("boto3.resource")
def test_empty_body_is_rejected_not_a_json_error(mock_resource):
    response = app.handler(_event(None), None)

    assert response["statusCode"] == 400
