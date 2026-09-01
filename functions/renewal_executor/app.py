"""renewal-executor-fn: ACM-only auto-renewal. Never stores plaintext secret material."""
import os
import time

import boto3

from crm_common import structured_log

CERT_TABLE_NAME = os.environ["CERT_TABLE_NAME"]

# Allow-list mirrors discovery-acm-fn: guarantees no Secret/PrivateKey field can
# ever reach the inventory table from this function.
ALLOWED_UPDATE_FIELDS = {"ExpiryDate", "Status", "Version"}


def handler(event, context):
    """event: {"certId": "...", "certArn": "..."}"""
    request_id = getattr(context, "aws_request_id", "local")
    cert_id = event["certId"]
    cert_arn = event.get("certArn", cert_id)
    structured_log(request_id, "RENEWAL_EXECUTOR_START", certId=cert_id)

    acm = boto3.client("acm")
    table = boto3.resource("dynamodb").Table(CERT_TABLE_NAME)

    acm.renew_certificate(CertificateArn=cert_arn)
    structured_log(request_id, "RENEWAL_RENEW_CERTIFICATE_OK", certId=cert_id)
    detail = acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]

    update = {
        "ExpiryDate": detail.get("NotAfter").isoformat() if detail.get("NotAfter") else None,
        "Status": detail.get("Status", "ISSUED"),
        "Version": int(time.time()),
    }
    update = {k: v for k, v in update.items() if k in ALLOWED_UPDATE_FIELDS}

    table.update_item(
        Key={"CertId": cert_id},
        UpdateExpression="SET " + ", ".join(f"#{k} = :{k}" for k in update),
        ExpressionAttributeNames={f"#{k}": k for k in update},
        ExpressionAttributeValues={f":{k}": v for k, v in update.items()},
    )

    structured_log(
        request_id,
        "RENEWAL_EXECUTOR_COMPLETE",
        certId=cert_id,
        status=update.get("Status"),
        expiryDate=update.get("ExpiryDate"),
    )
    return {"certId": cert_id, "status": update.get("Status"), "expiryDate": update.get("ExpiryDate")}
