"""rotation-iam-key-fn: the Lambda invoked by the rotation state machine.

Deliberately makes ZERO IAM API calls (no CreateAccessKey/DeactivateAccessKey/
DeleteAccessKey). Automatically mutating a live access key is a high-blast
-radius, hard-to-reverse action — a caller still using that key would break
with no warning. This function only records that the account was flagged;
completing the actual key rotation is a deliberate, human, out-of-band step.
See README.md's Deviations section.
"""
from datetime import datetime, timezone

from crm_common import structured_log


def handler(event, context):
    request_id = getattr(context, "aws_request_id", "local")
    account_id_hash = event["accountIdHash"]
    structured_log(request_id, "ROTATION_IAM_KEY_FLAGGED", accountIdHash=account_id_hash, mode="NOTIFY_ONLY")
    return {
        "accountIdHash": account_id_hash,
        "flaggedAt": datetime.now(timezone.utc).isoformat(),
        "mode": "NOTIFY_ONLY",
    }
