"""expiry-evaluator-fn: hourly threshold scan across both inventories.

Publishes an SNS alert AND independently sends an SQS ticket-creation message
per match. The two fan-outs are intentionally decoupled (Requirement 4.3) —
a failure sending to SQS must never prevent the SNS publish, and vice versa.
"""
import json
import os
import time
from datetime import datetime, timedelta, timezone

import boto3
from crm_common import put_audit_event

CERT_TABLE_NAME = os.environ["CERT_TABLE_NAME"]
IAM_TABLE_NAME = os.environ["IAM_TABLE_NAME"]
JIRA_QUEUE_URL = os.environ["JIRA_QUEUE_URL"]
SNS_TOPIC_LOW = os.environ["SNS_TOPIC_LOW"]
SNS_TOPIC_MEDIUM = os.environ["SNS_TOPIC_MEDIUM"]
SNS_TOPIC_HIGH = os.environ["SNS_TOPIC_HIGH"]

# Days-to-expiry -> (severity, SNS topic env var already resolved at call time)
THRESHOLDS = [(30, "low"), (14, "medium"), (7, "high")]

_SEVERITY_TOPIC = {
    "low": SNS_TOPIC_LOW,
    "medium": SNS_TOPIC_MEDIUM,
    "high": SNS_TOPIC_HIGH,
}


def _severity_for(days_out):
    match = None
    for threshold_days, severity in THRESHOLDS:
        if days_out <= threshold_days:
            match = severity
    return match


def _publish_alert(sns, resource_id, resource_type, severity, expiry_value):
    topic_arn = _SEVERITY_TOPIC[severity]
    sns.publish(
        TopicArn=topic_arn,
        Subject=f"{resource_type} {resource_id} expiring soon ({severity})",
        Message=json.dumps(
            {
                "resourceId": resource_id,
                "resourceType": resource_type,
                "severity": severity,
                "expiry": expiry_value,
            }
        ),
    )


def _send_ticket_request(sqs, resource_id, resource_type, severity, expiry_value):
    sqs.send_message(
        QueueUrl=JIRA_QUEUE_URL,
        MessageBody=json.dumps(
            {
                "resourceId": resource_id,
                "resourceType": resource_type,
                "severity": severity,
                "expiry": expiry_value,
            }
        ),
    )


def handler(event, context):
    dynamodb = boto3.resource("dynamodb")
    sns = boto3.client("sns")
    sqs = boto3.client("sqs")

    matches = []

    cert_table = dynamodb.Table(CERT_TABLE_NAME)
    horizon = max(days for days, _ in THRESHOLDS)
    cutoff = (datetime.now(timezone.utc) + timedelta(days=horizon)).isoformat()
    cert_response = cert_table.query(
        IndexName="ExpiryIndex",
        KeyConditionExpression="#s = :status AND #e <= :cutoff",
        ExpressionAttributeNames={"#s": "Status", "#e": "ExpiryDate"},
        ExpressionAttributeValues={":status": "ISSUED", ":cutoff": cutoff},
    )
    for item in cert_response.get("Items", []):
        matches.append(("cert", item["CertId"], item.get("ExpiryDate")))

    iam_table = dynamodb.Table(IAM_TABLE_NAME)
    iam_response = iam_table.query(
        IndexName="StatusIndex",
        KeyConditionExpression="#s = :status AND #e <= :cutoff",
        ExpressionAttributeNames={"#s": "Status", "#e": "NextRotationDate"},
        ExpressionAttributeValues={":status": "active", ":cutoff": cutoff},
    )
    for item in iam_response.get("Items", []):
        matches.append(("iam-account", item["AccountIdHash"], item.get("NextRotationDate")))

    now = datetime.now(timezone.utc)
    alerted = 0
    for resource_type, resource_id, expiry_value in matches:
        try:
            days_out = (datetime.fromisoformat(expiry_value) - now).days if expiry_value else 0
        except ValueError:
            days_out = 0
        severity = _severity_for(days_out)
        if severity is None:
            continue

        # Independent fan-out: SNS publish failure must not skip the SQS send, and vice versa.
        try:
            _publish_alert(sns, resource_id, resource_type, severity, expiry_value)
        finally:
            _send_ticket_request(sqs, resource_id, resource_type, severity, expiry_value)

        put_audit_event(
            entity_id=resource_id,
            event_type="EXPIRY_ALERT",
            actor="expiry-evaluator-fn",
            outcome="ALERTED",
            detail={"severity": severity, "expiry": expiry_value, "resourceType": resource_type},
        )
        alerted += 1

    return {"evaluated": len(matches), "alerted": alerted}
