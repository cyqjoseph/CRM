"""An unhandled exception in a browser-facing handler must not become a 502.

API Gateway answers 502 Bad Gateway when a proxy-integration Lambda raises or
returns a malformed response. That response carries no CORS headers, so the
browser reports a CORS failure, the UI shows "Failed to fetch", and the actual
reason exists only in CloudWatch — the same invisibility problem as a rollback
that reports nothing but "Resource creation cancelled".

These API Gateway-fronted handlers therefore catch, log and return a
well-formed 500.

The event-driven functions deliberately do NOT do this: expiry_evaluator,
jira_notifier and discovery_iam must keep raising so Step Functions
retries and SQS redrive-to-DLQ still work.
"""
import json
from unittest.mock import MagicMock, patch

import pytest
from conftest import load_module

API_MODULES = {
    "certs": ("api_certs_err", "functions/api_certs/app.py"),
    "iam": ("api_iam_err", "functions/api_iam/app.py"),
    "audit": ("api_audit_err", "functions/api_audit/app.py"),
    "sync": ("sync_on_prem_err", "functions/sync_on_prem/app.py"),
}

EVENTS = {
    "certs": {"httpMethod": "GET", "resource": "/certs"},
    "iam": {"httpMethod": "GET", "resource": "/iam/accounts"},
    "audit": {"httpMethod": "GET", "resource": "/audit"},
    "sync": {"httpMethod": "POST", "resource": "/sync/on-prem-data"},
}


def _event(name):
    event = dict(EVENTS[name])
    event["pathParameters"] = None
    event["queryStringParameters"] = {"entityId": "owner-1"} if name == "audit" else None
    event["requestContext"] = {"authorizer": {"claims": {"sub": "owner-1"}}}
    if name == "sync":
        event["body"] = json.dumps({"table": "certificates", "item": {"CertId": "x"}})
    return event


@pytest.mark.parametrize("name", sorted(API_MODULES))
@patch("boto3.resource")
@patch("boto3.client")
def test_api_handler_returns_500_instead_of_raising(mock_client, mock_resource, name):
    app = load_module(*API_MODULES[name])

    table = MagicMock()
    boom = RuntimeError("DynamoDB exploded")
    table.query.side_effect = boom
    table.get_item.side_effect = boom
    table.scan.side_effect = boom
    table.put_item.side_effect = boom
    mock_resource.return_value.Table.return_value = table
    mock_client.side_effect = boom

    response = app.handler(_event(name), None)

    assert isinstance(response, dict), "handler must return a response, not raise"
    assert response["statusCode"] == 500, (
        f"{name} handler returned {response.get('statusCode')} — an unhandled "
        "exception must become a 500, not propagate into a 502"
    )
    # The shape has to stay valid or API Gateway still emits 502.
    assert "Access-Control-Allow-Origin" in response["headers"]
    body = json.loads(response["body"])
    assert "message" in body
    # Never leak internals to the browser; the traceback belongs in CloudWatch.
    assert "DynamoDB exploded" not in response["body"]


@pytest.mark.parametrize("name", sorted(API_MODULES))
@patch("boto3.resource")
@patch("boto3.client")
def test_api_handler_logs_the_traceback(mock_client, mock_resource, name, capsys):
    app = load_module(*API_MODULES[name])

    table = MagicMock()
    boom = RuntimeError("DynamoDB exploded")
    table.query.side_effect = boom
    table.get_item.side_effect = boom
    table.scan.side_effect = boom
    table.put_item.side_effect = boom
    mock_resource.return_value.Table.return_value = table
    mock_client.side_effect = boom

    app.handler(_event(name), None)

    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "DynamoDB exploded" in combined, (
        "the real error must reach stdout/stderr so it lands in CloudWatch"
    )
    assert "Traceback" in combined


def test_event_driven_functions_still_raise():
    """Regression guard: swallowing here would break retries and DLQ redrive."""
    from crm_common import api_response  # noqa: F401  (import sanity)

    source = (
        __import__("pathlib").Path(__file__).resolve().parent.parent
        / "functions"
        / "jira_notifier"
        / "app.py"
    ).read_text()
    assert "guard_api_handler" not in source, (
        "jira_notifier must not use the API error guard — it relies on raising so "
        "SQS's redrive policy moves the message to the DLQ"
    )
