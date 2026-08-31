"""renewal-executor-fn: ACM-only auto-renewal. Never stores plaintext secret material."""
import os
import time

import boto3

CERT_TABLE_NAME = os.environ["CERT_TABLE_NAME"]

# Allow-list mirrors discovery-acm-fn: guarantees no Secret/PrivateKey field can
# ever reach the inventory table from this function.
ALLOWED_UPDATE_FIELDS = {"ExpiryDate", "Status", "Version"}


def handler(event, context):
    """event: {"certId": "...", "certArn": "..."}"""
    cert_id = event["certId"]
    cert_arn = event.get("certArn", cert_id)

    acm = boto3.client("acm")
    table = boto3.resource("dynamodb").Table(CERT_TABLE_NAME)

    acm.renew_certificate(CertificateArn=cert_arn)
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

    return {"certId": cert_id, "status": update.get("Status"), "expiryDate": update.get("ExpiryDate")}
