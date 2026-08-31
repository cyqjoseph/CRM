"""password-reset-approver-fn: admin-only POST /password-resets/{requestId}/approve
and POST /password-resets/{requestId}/reject.

Approve starts the password-reset state machine (which performs the actual
credential generation — see password-reset-executor-fn); reject only updates
the request and notifies the user. Neither branch ever sees a plaintext
password — that only exists inside the executor's own invocation.
"""
import json
import os

import boto3
from crm_common import (
    api_response,
    get_claims,
    guard_api_handler,
    is_admin,
    new_request_id,
    now_iso,
    owner_id_of,
    put_audit_event,
)

PASSWORD_RESET_TABLE_NAME = os.environ["PASSWORD_RESET_TABLE_NAME"]
PASSWORD_RESET_STATE_MACHINE_ARN = os.environ["PASSWORD_RESET_STATE_MACHINE_ARN"]
NOTIFICATIONS_TOPIC_ARN = os.environ["PASSWORD_RESET_NOTIFICATIONS_TOPIC_ARN"]


def _find_pending_request(table, request_id):
    response = table.query(
        KeyConditionExpression="RequestId = :r",
        ExpressionAttributeValues={":r": request_id},
    )
    items = response.get("Items", [])
    return items[0] if items else None


def _approve(table, claims, request_id):
    item = _find_pending_request(table, request_id)
    if not item:
        return api_response(404, {"message": "not found"})
    if item.get("Status") != "pending":
        return api_response(409, {"message": f"request is {item.get('Status')}, not pending"})

    admin_id = owner_id_of(claims)
    table.update_item(
        Key={"RequestId": item["RequestId"], "Timestamp": item["Timestamp"]},
        UpdateExpression="SET #s = :status, AdminApprover = :approver, ApprovalTimestamp = :approvedAt",
        ExpressionAttributeNames={"#s": "Status"},
        ExpressionAttributeValues={
            ":status": "approved",
            ":approver": admin_id,
            ":approvedAt": now_iso(),
        },
    )

    sfn = boto3.client("stepfunctions")
    execution_name = new_request_id()
    execution = sfn.start_execution(
        stateMachineArn=PASSWORD_RESET_STATE_MACHINE_ARN,
        name=execution_name,
        input=json.dumps(
            {
                "requestId": item["RequestId"],
                "accountId": item["AccountId"],
                "timestamp": item["Timestamp"],
                "requestedBy": item.get("RequestedBy", ""),
            }
        ),
    )

    put_audit_event(
        entity_id=item["AccountId"],
        event_type="PASSWORD_RESET_APPROVED",
        actor=admin_id,
        outcome="STARTED",
        detail={"requestId": request_id, "executionArn": execution["executionArn"]},
    )

    return api_response(202, {"executionArn": execution["executionArn"], "requestId": request_id})


def _reject(table, claims, request_id):
    item = _find_pending_request(table, request_id)
    if not item:
        return api_response(404, {"message": "not found"})
    if item.get("Status") != "pending":
        return api_response(409, {"message": f"request is {item.get('Status')}, not pending"})

    admin_id = owner_id_of(claims)
    table.update_item(
        Key={"RequestId": item["RequestId"], "Timestamp": item["Timestamp"]},
        UpdateExpression="SET #s = :status, AdminApprover = :approver, ApprovalTimestamp = :approvedAt",
        ExpressionAttributeNames={"#s": "Status"},
        ExpressionAttributeValues={
            ":status": "rejected",
            ":approver": admin_id,
            ":approvedAt": now_iso(),
        },
    )

    sns = boto3.client("sns")
    sns.publish(
        TopicArn=NOTIFICATIONS_TOPIC_ARN,
        Subject="Password reset request rejected",
        Message="Your password reset request was rejected. Contact admin for details.",
    )

    put_audit_event(
        entity_id=item["AccountId"],
        event_type="PASSWORD_RESET_REJECTED",
        actor=admin_id,
        outcome="SUCCESS",
        detail={"requestId": request_id},
    )

    return api_response(200, {"requestId": request_id, "status": "rejected"})


@guard_api_handler
def handler(event, context):
    claims = get_claims(event)
    if not is_admin(claims):
        return api_response(403, {"message": "forbidden"})

    table = boto3.resource("dynamodb").Table(PASSWORD_RESET_TABLE_NAME)
    path_params = event.get("pathParameters") or {}
    request_id = path_params.get("requestId")
    resource_path = event.get("resource", "")

    if event.get("httpMethod") == "POST" and resource_path.endswith("/approve"):
        return _approve(table, claims, request_id)
    if event.get("httpMethod") == "POST" and resource_path.endswith("/reject"):
        return _reject(table, claims, request_id)

    return api_response(404, {"message": "not found"})
