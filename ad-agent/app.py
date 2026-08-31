"""ad-agent: on-prem AD discovery/rotation task, run as an ECS Fargate task.

This sandbox account has no Direct Connect/VPN to a real on-prem AD, so this
agent simulates the LDAP/ADWS directory it would otherwise query — the shape
of the work (bind with Secrets Manager credentials, enumerate accounts, hash
identifiers, write lifecycle-only metadata) matches what a real deployment
against on-prem AD would do; only the network call is stubbed.

Mode is selected via the AD_TASK_MODE env var: DISCOVER or ROTATE.
"""
import hashlib
import os
import time
from datetime import datetime, timedelta, timezone

import boto3

AD_TABLE_NAME = os.environ["AD_TABLE_NAME"]
AUDIT_TABLE_NAME = os.environ["AUDIT_TABLE_NAME"]
AD_BIND_SECRET_ARN = os.environ["AD_BIND_SECRET_ARN"]
AD_TASK_MODE = os.environ.get("AD_TASK_MODE", "DISCOVER")
AD_DOMAIN = os.environ.get("AD_DOMAIN", "corp.example.internal")
ROTATION_ACCOUNT_HASH = os.environ.get("ROTATION_ACCOUNT_HASH")

# Simulated directory: real accounts an on-prem LDAP bind would return.
_SIMULATED_ACCOUNTS = [
    {"sam_account_name": "svc-payments-01", "owner_id": "owner-payments"},
    {"sam_account_name": "svc-billing-02", "owner_id": "owner-billing"},
    {"sam_account_name": "svc-crm-agent", "owner_id": "owner-platform"},
]


def hash_identifier(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _bind_to_ad(secretsmanager):
    """Fetches bind credentials; never logs or persists them."""
    secretsmanager.get_secret_value(SecretId=AD_BIND_SECRET_ARN)
    return True


def _put_audit_event(dynamodb, entity_id, event_type, outcome, detail=None):
    table = dynamodb.Table(AUDIT_TABLE_NAME)
    now = int(time.time())
    table.put_item(
        Item={
            "EntityId": entity_id,
            "EventTimestamp": datetime.now(timezone.utc).isoformat(),
            "EventType": event_type,
            "Actor": "ad-agent",
            "Outcome": outcome,
            "Detail": detail or {},
            "ExpiresAt": now + 90 * 86400,
        }
    )


def discover(dynamodb, secretsmanager):
    _bind_to_ad(secretsmanager)
    table = dynamodb.Table(AD_TABLE_NAME)
    next_rotation = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()

    written = 0
    for account in _SIMULATED_ACCOUNTS:
        account_id_hash = hash_identifier(f"{AD_DOMAIN}\\{account['sam_account_name']}")
        table.put_item(
            Item={
                "AccountIdHash": account_id_hash,
                "OwnerId": account["owner_id"],
                "Domain": AD_DOMAIN,
                "NextRotationDate": next_rotation,
                "RotationStatus": "ACTIVE",
            }
        )
        _put_audit_event(dynamodb, account_id_hash, "AD_DISCOVERY", "SUCCESS")
        written += 1

    return written


def rotate(dynamodb, secretsmanager):
    if not ROTATION_ACCOUNT_HASH:
        raise ValueError("ROTATION_ACCOUNT_HASH is required for AD_TASK_MODE=ROTATE")

    _bind_to_ad(secretsmanager)
    table = dynamodb.Table(AD_TABLE_NAME)
    next_rotation = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()

    table.update_item(
        Key={"AccountIdHash": ROTATION_ACCOUNT_HASH},
        UpdateExpression="SET NextRotationDate = :next, RotationStatus = :status",
        ExpressionAttributeValues={":next": next_rotation, ":status": "ACTIVE"},
    )
    _put_audit_event(dynamodb, ROTATION_ACCOUNT_HASH, "AD_ROTATION", "SUCCESS")
    return 1


def main():
    dynamodb = boto3.resource("dynamodb")
    secretsmanager = boto3.client("secretsmanager")

    if AD_TASK_MODE == "ROTATE":
        count = rotate(dynamodb, secretsmanager)
    else:
        count = discover(dynamodb, secretsmanager)

    print(f"ad-agent mode={AD_TASK_MODE} processed={count}")


if __name__ == "__main__":
    main()
