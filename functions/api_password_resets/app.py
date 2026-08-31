"""api-password-resets-fn: POST /password-resets, GET /password-resets.

Creating a request never resets anything itself — it only appends a `pending`
row for an admin to review (see password-reset-approver-fn). GET is an
admin-only dashboard query; a non-admin's own request status is returned
directly from the POST response, so no self-scoped GET is needed.
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
IAM_TABLE_NAME = os.environ["IAM_TABLE_NAME"]


def _create_request(table, iam_table, claims, body):
    owner_id = owner_id_of(claims)
    if not owner_id:
        return api_response(401, {"message": "unauthenticated"})

    body = body or {}
    account_id = body.get("accountId")
    if not account_id:
        return api_response(400, {"message": "accountId is required"})

    account = iam_table.get_item(Key={"AccountIdHash": account_id}).get("Item")
    if not account:
        return api_response(404, {"message": "not found"})
    if not is_admin(claims) and account.get("OwnerId") != owner_id:
        return api_response(404, {"message": "not found"})

    request_id = new_request_id()
    item = {
        "RequestId": request_id,
        "Timestamp": now_iso(),
        "AccountId": account_id,
        "RequestedBy": owner_id,
        "Reason": body.get("reason", ""),
        "Status": "pending",
    }
    table.put_item(Item=item)

    put_audit_event(
        entity_id=account_id,
        event_type="PASSWORD_RESET_REQUESTED",
        actor=owner_id,
        outcome="STARTED",
        detail={"requestId": request_id},
    )

    return api_response(201, item)


def _list_requests(table, claims, query_params):
    if not is_admin(claims):
        return api_response(403, {"message": "forbidden"})

    query_params = query_params or {}
    status = query_params.get("status")
    date_from = query_params.get("from")
    date_to = query_params.get("to")

    if status:
        key_condition = "#s = :status"
        values = {":status": status}
        if date_from and date_to:
            key_condition += " AND #ts BETWEEN :from AND :to"
            values[":from"] = date_from
            values[":to"] = date_to
        response = table.query(
            IndexName="StatusIndex",
            KeyConditionExpression=key_condition,
            ExpressionAttributeNames={"#s": "Status", "#ts": "Timestamp"},
            ExpressionAttributeValues=values,
        )
        items = response.get("Items", [])
    else:
        response = table.scan()
        items = response.get("Items", [])
        if date_from and date_to:
            items = [i for i in items if date_from <= i.get("Timestamp", "") <= date_to]

    return api_response(200, {"items": items})


@guard_api_handler
def handler(event, context):
    claims = get_claims(event)
    table = boto3.resource("dynamodb").Table(PASSWORD_RESET_TABLE_NAME)

    method = event.get("httpMethod")
    if method == "POST":
        iam_table = boto3.resource("dynamodb").Table(IAM_TABLE_NAME)
        body = json.loads(event["body"]) if event.get("body") else {}
        return _create_request(table, iam_table, claims, body)
    if method == "GET":
        return _list_requests(table, claims, event.get("queryStringParameters"))

    return api_response(404, {"message": "not found"})
