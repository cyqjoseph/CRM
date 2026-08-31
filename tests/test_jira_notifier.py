import json
from unittest.mock import MagicMock, patch

import pytest

from conftest import load_module

app = load_module("jira_notifier_app", "functions/jira_notifier/app.py")


def _sqs_event(resource_id="cert-1"):
    return {
        "Records": [
            {
                "body": json.dumps(
                    {
                        "resourceId": resource_id,
                        "resourceType": "cert",
                        "severity": "high",
                        "expiry": "2026-09-01T00:00:00+00:00",
                    }
                )
            }
        ]
    }


@patch("urllib3.PoolManager")
@patch("boto3.client")
def test_success_creates_ticket(mock_client, mock_pool_manager):
    secretsmanager = MagicMock()
    secretsmanager.get_secret_value.return_value = {"SecretString": "tok"}
    mock_client.return_value = secretsmanager

    http_client = MagicMock()
    http_client.request.return_value = MagicMock(status=201, data=b'{"key":"CRM-1"}')
    mock_pool_manager.return_value = http_client

    result = app.handler(_sqs_event(), None)
    assert result["processed"] == 1
    assert http_client.request.called


@patch("urllib3.PoolManager")
@patch("boto3.client")
def test_jira_failure_raises_so_sqs_leaves_message_for_dlq_redrive(mock_client, mock_pool_manager):
    """The function must raise (not swallow) on a Jira failure: with the queue's
    BatchSize=1 and maxReceiveCount redrive policy, an unhandled raise here is
    exactly what leaves the message unacknowledged so SQS moves it to the DLQ
    after retries — silently succeeding would drop the ticket instead."""
    secretsmanager = MagicMock()
    secretsmanager.get_secret_value.return_value = {"SecretString": "tok"}
    mock_client.return_value = secretsmanager

    http_client = MagicMock()
    http_client.request.return_value = MagicMock(status=500, data=b"{}")
    mock_pool_manager.return_value = http_client

    with pytest.raises(RuntimeError):
        app.handler(_sqs_event(), None)
