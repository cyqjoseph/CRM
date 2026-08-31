"""audit-exporter-fn: streams the audit-hot DynamoDB table to the S3 archive before TTL expiry.

Key layout: {entityType}/{yyyy}/{mm}/{dd}/{entityId}-{eventTimestamp}.json
"""
import json
import os
from datetime import datetime, timezone

import boto3

ARCHIVE_BUCKET_NAME = os.environ["ARCHIVE_BUCKET_NAME"]


CERT_ARN_PREFIXES = ("arn:aws:acm", "arn:aws:iam", "arn:aws:secretsmanager")


def _entity_type(entity_id):
    if entity_id.startswith(CERT_ARN_PREFIXES):
        return "cert"
    return "ad-account"


def _image_to_plain(image):
    plain = {}
    for key, typed_value in image.items():
        if "S" in typed_value:
            plain[key] = typed_value["S"]
        elif "N" in typed_value:
            plain[key] = typed_value["N"]
        elif "M" in typed_value:
            plain[key] = {k: list(v.values())[0] for k, v in typed_value["M"].items()}
        else:
            plain[key] = typed_value
    return plain


def handler(event, context):
    s3 = boto3.client("s3")
    exported = 0

    for record in event.get("Records", []):
        if record.get("eventName") not in ("INSERT", "MODIFY"):
            continue

        image = record["dynamodb"].get("NewImage")
        if not image:
            continue

        item = _image_to_plain(image)
        entity_id = item["EntityId"]
        event_timestamp = item["EventTimestamp"]
        entity_type = _entity_type(entity_id)
        dt = datetime.fromisoformat(event_timestamp)

        key = (
            f"{entity_type}/{dt.strftime('%Y')}/{dt.strftime('%m')}/{dt.strftime('%d')}/"
            f"{entity_id.replace('/', '_')}-{event_timestamp.replace(':', '')}.json"
        )

        s3.put_object(
            Bucket=ARCHIVE_BUCKET_NAME,
            Key=key,
            Body=json.dumps(item).encode("utf-8"),
            ContentType="application/json",
        )
        exported += 1

    return {"exported": exported}
