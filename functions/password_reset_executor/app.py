"""password-reset-executor-fn: invoked by the password-reset state machine.

Generates a temporary password, hashes it, and stores only the hash plus
metadata in the static credentials secret, keyed by requestId. The plaintext
value is never returned, logged, or persisted anywhere — this prototype has
no allowed way to email it (SES is not an allowed service), so delivery is
deliberately out of scope. See README.md's Deviations section.
"""
import hashlib
import json
import os
import secrets
import string

import boto3

CREDENTIALS_SECRET_ARN = os.environ["PASSWORD_RESET_CREDENTIALS_SECRET_ARN"]

_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*"


def _generate_temporary_password(length=16):
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


def handler(event, context):
    request_id = event["requestId"]
    account_id = event["accountId"]
    timestamp = event["timestamp"]

    sm = boto3.client("secretsmanager")
    existing = json.loads(sm.get_secret_value(SecretId=CREDENTIALS_SECRET_ARN)["SecretString"] or "{}")

    temporary_password = _generate_temporary_password()
    password_hash = hashlib.sha256(temporary_password.encode("utf-8")).hexdigest()
    del temporary_password

    existing[request_id] = {
        "accountId": account_id,
        "passwordHash": password_hash,
        "timestamp": timestamp,
    }

    sm.put_secret_value(SecretId=CREDENTIALS_SECRET_ARN, SecretString=json.dumps(existing))

    return {"requestId": request_id, "accountId": account_id, "timestamp": timestamp}
