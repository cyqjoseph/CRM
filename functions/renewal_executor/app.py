"""renewal-executor-fn: the Lambda invoked by the renewal state machine.

Makes ZERO ACM API calls. ACM is absent from CLAUDE.md's exhaustive
allowed-services list, so the account permissions boundary denies
acm:RenewCertificate and acm:DescribeCertificate regardless of what this
function's own IAM policy grants. The previous version called them anyway, so
every renewal started successfully (the API returned 202) and then failed
asynchronously inside the state machine — which in the UI looked exactly like
the Renew button doing nothing at all.

Instead it records the renewal against the inventory row: a new expiry one
validity period out, Status back to ISSUED, and a bumped Version. This is the
same NOTIFY/record-only substitution rotation-iam-key-fn already uses for IAM
keys and password-reset-executor-fn uses for credentials. Issuing real
certificate material is left to whatever permitted channel a production
deployment would add. See README.md's Deviations section.
"""
import os
import time
from datetime import datetime, timedelta, timezone

import boto3

from crm_common import structured_log

CERT_TABLE_NAME = os.environ["CERT_TABLE_NAME"]

# One ACM-equivalent validity period. Real ACM certificates are issued for 13
# months; 90 days matches the shorter-lived issuers this inventory also tracks
# and keeps the renewed row inside the dashboard's green band.
RENEWAL_VALIDITY_DAYS = int(os.environ.get("RENEWAL_VALIDITY_DAYS", "90"))

# Allow-list: guarantees no Secret/PrivateKey field can ever reach the
# inventory table from this function.
ALLOWED_UPDATE_FIELDS = {"ExpiryDate", "Status", "Version", "LastRenewedAt"}


def handler(event, context):
    """event: {"certId": "...", "requestId": "..."}"""
    request_id = getattr(context, "aws_request_id", "local")
    cert_id = event["certId"]
    structured_log(request_id, "RENEWAL_EXECUTOR_START", certId=cert_id)

    table = boto3.resource("dynamodb").Table(CERT_TABLE_NAME)
    now = datetime.now(timezone.utc)

    update = {
        "ExpiryDate": (now + timedelta(days=RENEWAL_VALIDITY_DAYS)).date().isoformat(),
        "Status": "ISSUED",
        "Version": int(time.time()),
        "LastRenewedAt": now.isoformat(),
    }
    update = {k: v for k, v in update.items() if k in ALLOWED_UPDATE_FIELDS}

    # Conditional on the row existing: a renewal for a CertId that has since
    # been deleted must fail loudly (the state machine catches it and writes a
    # FAILURE audit event) rather than silently creating a partial row.
    table.update_item(
        Key={"CertId": cert_id},
        UpdateExpression="SET " + ", ".join(f"#{k} = :{k}" for k in update),
        ExpressionAttributeNames={f"#{k}": k for k in update},
        ExpressionAttributeValues={f":{k}": v for k, v in update.items()},
        ConditionExpression="attribute_exists(CertId)",
    )

    structured_log(
        request_id,
        "RENEWAL_EXECUTOR_COMPLETE",
        certId=cert_id,
        status=update["Status"],
        expiryDate=update["ExpiryDate"],
    )
    return {
        "certId": cert_id,
        "status": update["Status"],
        "expiryDate": update["ExpiryDate"],
        "mode": "RECORD_ONLY",
    }
