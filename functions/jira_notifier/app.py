"""jira-notifier-fn: SQS-triggered Jira ticket creation.

A per-record failure raises, which SQS uses to leave that single message
unacknowledged; after the queue's maxReceiveCount is exhausted the redrive
policy moves it to the DLQ. This function never blocks or retracts the SNS
alert that was already sent by the expiry evaluator (Requirement 4.4).
"""
import json
import os

import boto3

JIRA_TOKEN_SECRET_ARN = os.environ["JIRA_TOKEN_SECRET_ARN"]
JIRA_BASE_URL = os.environ.get("JIRA_BASE_URL", "https://example.atlassian.net")

_secrets_cache = {}


def _jira_token():
    if "token" not in _secrets_cache:
        secretsmanager = boto3.client("secretsmanager")
        value = secretsmanager.get_secret_value(SecretId=JIRA_TOKEN_SECRET_ARN)
        _secrets_cache["token"] = value["SecretString"]
    return _secrets_cache["token"]


def _create_ticket(http_client, resource_id, resource_type, severity, expiry):
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
        raise RuntimeError(f"Jira ticket creation failed with status {response.status}")
    return json.loads(response.data)


def handler(event, context):
    import urllib3

    http_client = urllib3.PoolManager()

    for record in event.get("Records", []):
        payload = json.loads(record["body"])
        # Any exception here leaves this record unacknowledged; SQS redrives
        # it and, after maxReceiveCount, moves it to the DLQ untouched.
        _create_ticket(
            http_client,
            payload["resourceId"],
            payload["resourceType"],
            payload["severity"],
            payload.get("expiry"),
        )

    return {"processed": len(event.get("Records", []))}
