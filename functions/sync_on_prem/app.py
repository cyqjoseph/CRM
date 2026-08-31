"""sync-on-prem-fn: stub proxy for future on-prem (Ansible-driven) inventory sync.

POST /sync/on-prem-data body: {"table": "certificates" | "iam-accounts", "item": {...}}

Not wired to any real on-prem system today — this exists so the Ansible
report-to-dynamodb role stub (see ansible/roles/report-to-dynamodb) has a
concrete HTTP target to call once it is implemented.
"""
import json
import os

import boto3
from crm_common import api_response, guard_api_handler

CERT_TABLE_NAME = os.environ["CERT_TABLE_NAME"]
IAM_TABLE_NAME = os.environ["IAM_TABLE_NAME"]

TABLE_NAMES = {
    "certificates": CERT_TABLE_NAME,
    "iam-accounts": IAM_TABLE_NAME,
}


@guard_api_handler
def handler(event, context):
    body = json.loads(event.get("body") or "{}")
    table_key = body.get("table")
    item = body.get("item")

    if table_key not in TABLE_NAMES or not isinstance(item, dict):
        return api_response(400, {"message": "expected {table, item}"})

    # TODO: Add payload validation, audit logging
    table = boto3.resource("dynamodb").Table(TABLE_NAMES[table_key])
    table.put_item(Item=item)

    return api_response(202, {"table": table_key})
