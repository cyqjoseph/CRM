import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from conftest import load_module

app = load_module("expiry_evaluator_app", "functions/expiry_evaluator/app.py")


def _soon(days):
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def _mock_dynamo(cert_items, ad_items):
    dynamodb = MagicMock()
    cert_table = MagicMock()
    ad_table = MagicMock()
    audit_table = MagicMock()
    cert_table.query.return_value = {"Items": cert_items}
    ad_table.query.return_value = {"Items": ad_items}

    def table_side_effect(name):
        return {
            app.CERT_TABLE_NAME: cert_table,
            app.AD_TABLE_NAME: ad_table,
            os.environ["AUDIT_TABLE_NAME"]: audit_table,
        }[name]

    dynamodb.Table.side_effect = table_side_effect
    return dynamodb


@patch("boto3.resource")
@patch("boto3.client")
def test_sns_publish_and_sqs_send_both_called(mock_client, mock_resource):
    cert_items = [{"CertId": "cert-1", "ExpiryDate": _soon(5)}]
    mock_resource.return_value = _mock_dynamo(cert_items, [])

    sns = MagicMock()
    sqs = MagicMock()

    def client_side_effect(service_name, *a, **kw):
        return {"sns": sns, "sqs": sqs}[service_name]

    mock_client.side_effect = client_side_effect

    result = app.handler({}, None)

    assert sns.publish.called
    assert sqs.send_message.called
    assert result["alerted"] == 1


@patch("boto3.resource")
@patch("boto3.client")
def test_sqs_send_still_happens_when_sns_publish_fails(mock_client, mock_resource):
    """The two fan-outs are independent: an SNS failure must not skip the SQS send."""
    cert_items = [{"CertId": "cert-1", "ExpiryDate": _soon(5)}]
    mock_resource.return_value = _mock_dynamo(cert_items, [])

    sns = MagicMock()
    sns.publish.side_effect = RuntimeError("sns unavailable")
    sqs = MagicMock()

    def client_side_effect(service_name, *a, **kw):
        return {"sns": sns, "sqs": sqs}[service_name]

    mock_client.side_effect = client_side_effect

    with pytest.raises(RuntimeError):
        app.handler({}, None)

    assert sns.publish.called
    assert sqs.send_message.called
