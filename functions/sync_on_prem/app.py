"""sync-on-prem-fn: stub proxy for future on-prem (Ansible-driven) inventory sync.

POST /sync/on-prem-data body: {"table": "certificates" | "iam-accounts", "item": {...}}

Not wired to any real on-prem system today — this exists so the Ansible
report-to-dynamodb role stub (see ansible/roles/report-to-dynamodb) has a
concrete HTTP target to call once it is implemented.
"""
import json
import os

import boto3
from crm_common import api_response, guard_api_handler, put_audit_event, structured_log

CERT_TABLE_NAME = os.environ["CERT_TABLE_NAME"]
IAM_TABLE_NAME = os.environ["IAM_TABLE_NAME"]

TABLE_NAMES = {
    "certificates": CERT_TABLE_NAME,
    "iam-accounts": IAM_TABLE_NAME,
}

# Same guarantee as discovery-acm-fn/discovery-iam-fn: an on-prem payload is
# untrusted input, so it is allow-listed field-by-field before it ever reaches
# DynamoDB — no secret/key-material field can be smuggled in via this route.
ALLOWED_FIELDS = {
    "certificates": {
        "CertId",
        "CertType",
        "OwnerId",
        "Domain",
        "ExpiryDate",
        "Status",
        "Source",
        "Version",
        "EnvironmentTag",
        "LastSyncedAt",
    },
    "iam-accounts": {
        "AccountIdHash",
        "UserName",
        "OwnerId",
        "LastRotated",
        "NextRotationDate",
        "KeyAge",
        "Status",
        "Source",
        "EnvironmentTag",
        "LastSyncedAt",
        "Version",
    },
}

ENTITY_ID_FIELD = {
    "certificates": "CertId",
    "iam-accounts": "AccountIdHash",
}


@guard_api_handler
def handler(event, context):
    request_id = getattr(context, "aws_request_id", "local")
    body = json.loads(event.get("body") or "{}")
    table_key = body.get("table")
    item = body.get("item")

    if table_key not in TABLE_NAMES or not isinstance(item, dict):
        return api_response(400, {"message": "expected {table, item}"})

    sanitized = {k: v for k, v in item.items() if k in ALLOWED_FIELDS[table_key]}

    table = boto3.resource("dynamodb").Table(TABLE_NAMES[table_key])
    table.put_item(Item=sanitized)
    structured_log(request_id, "SYNC_ON_PREM_WRITE_OK", table=table_key)

    entity_id = sanitized.get(ENTITY_ID_FIELD[table_key], "unknown")
    put_audit_event(
        entity_id=entity_id,
        event_type="SYNC_ON_PREM_DATA",
        actor="sync-on-prem-fn",
        outcome="SYNCED",
        detail={"table": table_key},
    )

    return api_response(202, {"table": table_key})
