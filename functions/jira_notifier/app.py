"""jira-notifier-fn: SQS-triggered Jira ticket creation.

A per-record failure raises, which SQS uses to leave that single message
unacknowledged; after the queue's maxReceiveCount is exhausted the redrive
policy moves it to the DLQ. This function never blocks or retracts the SNS
alert that was already sent by the expiry evaluator (Requirement 4.4).
"""
import json
import os

import boto3

from crm_common import structured_log

JIRA_TOKEN_SECRET_ARN = os.environ["JIRA_TOKEN_SECRET_ARN"]
JIRA_BASE_URL = os.environ.get("JIRA_BASE_URL", "https://example.atlassian.net")

_secrets_cache = {}


def _jira_token():
    if "token" not in _secrets_cache:
        secretsmanager = boto3.client("secretsmanager")
        value = secretsmanager.get_secret_value(SecretId=JIRA_TOKEN_SECRET_ARN)
        _secrets_cache["token"] = value["SecretString"]
    return _secrets_cache["token"]


def _create_ticket(http_client, request_id, resource_id, resource_type, severity, expiry):
    token = _jira_token()
    body = json.dumps(
        {
            "fields": {
                "project": {"key": "CRM"},
                "summary": f"{resource_type} {resource_id} expiring ({severity})",
                "description": f"Expiry: {expiry}",
                "issuetype": {"name": "Task"},
            }
        }
    ).encode("utf-8")
    response = http_client.request(
        "POST",
        f"{JIRA_BASE_URL}/rest/api/2/issue",
        body=body,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    if response.status >= 300:
        structured_log(
            request_id, "JIRA_TICKET_CREATE_FAILED", level="ERROR", resourceId=resource_id, status=response.status
        )
        raise RuntimeError(f"Jira ticket creation failed with status {response.status}")
    structured_log(request_id, "JIRA_TICKET_CREATE_OK", resourceId=resource_id)
    return json.loads(response.data)


def handler(event, context):
    import urllib3

    request_id = getattr(context, "aws_request_id", "local")
    http_client = urllib3.PoolManager()
    records = event.get("Records", [])
    structured_log(request_id, "JIRA_NOTIFIER_START", recordCount=len(records))

    for record in records:
        payload = json.loads(record["body"])
        # Any exception here leaves this record unacknowledged; SQS redrives
        # it and, after maxReceiveCount, moves it to the DLQ untouched.
        _create_ticket(
            http_client,
            request_id,
            payload["resourceId"],
            payload["resourceType"],
            payload["severity"],
            payload.get("expiry"),
        )

    structured_log(request_id, "JIRA_NOTIFIER_COMPLETE", processed=len(records))
    return {"processed": len(records)}
