import json
import os
from unittest.mock import MagicMock, patch

from conftest import load_module

app = load_module("sync_on_prem_app", "functions/sync_on_prem/app.py")


def _event(body):
    return {
        "httpMethod": "POST",
        "resource": "/sync/on-prem-data",
        "body": json.dumps(body) if body is not None else None,
    }


def _mock_dynamodb(target_table):
    """Table() must resolve differently for the sync target vs. the audit
    table — both are fetched via the same boto3.resource("dynamodb")."""
    dynamodb = MagicMock()
    audit_table = MagicMock()

    def table_side_effect(name):
        if name == os.environ["AUDIT_TABLE_NAME"]:
            return audit_table
        return target_table

    dynamodb.Table.side_effect = table_side_effect
    return dynamodb, audit_table


@patch("boto3.resource")
def test_valid_payload_is_written_to_the_named_table(mock_resource):
    table = MagicMock()
    dynamodb, _audit_table = _mock_dynamodb(table)
    mock_resource.return_value = dynamodb

    response = app.handler(_event({"table": "certificates", "item": {"CertId": "onprem-1"}}), None)

    assert response["statusCode"] == 202
    table.put_item.assert_called_once_with(Item={"CertId": "onprem-1"})
    dynamodb.Table.assert_any_call(app.CERT_TABLE_NAME)


@patch("boto3.resource")
def test_fields_outside_the_allow_list_are_dropped_before_the_write(mock_resource):
    table = MagicMock()
    dynamodb, _audit_table = _mock_dynamodb(table)
    mock_resource.return_value = dynamodb

    response = app.handler(
        _event(
            {
                "table": "certificates",
                "item": {"CertId": "onprem-1", "PrivateKey": "MALICIOUS", "SecretValue": "MALICIOUS"},
            }
        ),
        None,
    )

    assert response["statusCode"] == 202
    written = table.put_item.call_args.kwargs["Item"]
    assert "PrivateKey" not in written
    assert "SecretValue" not in written
    assert written == {"CertId": "onprem-1"}


@patch("boto3.resource")
def test_sync_writes_an_audit_event(mock_resource):
    table = MagicMock()
    dynamodb, audit_table = _mock_dynamodb(table)
    mock_resource.return_value = dynamodb

    app.handler(_event({"table": "iam-accounts", "item": {"AccountIdHash": "hash-1"}}), None)

    assert audit_table.put_item.called
    item = audit_table.put_item.call_args.kwargs["Item"]
    assert item["EntityId"] == "hash-1"
    assert item["EventType"] == "SYNC_ON_PREM_DATA"


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
