"""api-ad-fn: GET /ad-accounts, GET /ad-accounts/{accountId}, POST /ad-accounts/{accountId}/rotate."""
import os

import boto3
from crm_common import api_response, get_claims, is_admin, new_request_id, owner_id_of, put_audit_event

AD_TABLE_NAME = os.environ["AD_TABLE_NAME"]
ROTATION_STATE_MACHINE_ARN = os.environ["ROTATION_STATE_MACHINE_ARN"]


def _list_accounts(table, claims, query_params):
    query_params = query_params or {}
    if is_admin(claims) and query_params.get("ownerId"):
        owner_id = query_params["ownerId"]
    else:
        owner_id = owner_id_of(claims)

    response = table.query(
        IndexName="OwnerIndex",
        KeyConditionExpression="OwnerId = :owner",
        ExpressionAttributeValues={":owner": owner_id},
    )
    items = response.get("Items", [])
    if query_params.get("status"):
        items = [i for i in items if i.get("RotationStatus") == query_params["status"]]
    return api_response(200, {"items": items})


def _get_account(table, claims, account_id):
    response = table.get_item(Key={"AccountIdHash": account_id})
    item = response.get("Item")
    if not item:
        return api_response(404, {"message": "not found"})
    if not is_admin(claims) and item.get("OwnerId") != owner_id_of(claims):
        return api_response(404, {"message": "not found"})
    return api_response(200, item)


def _rotate_account(table, claims, account_id):
    response = table.get_item(Key={"AccountIdHash": account_id})
    item = response.get("Item")
    if not item:
        return api_response(404, {"message": "not found"})
    if not is_admin(claims) and item.get("OwnerId") != owner_id_of(claims):
        return api_response(404, {"message": "not found"})

    sfn = boto3.client("stepfunctions")
    request_id = new_request_id()
    execution = sfn.start_execution(
        stateMachineArn=ROTATION_STATE_MACHINE_ARN,
        name=request_id,
        input='{"accountIdHash": "%s", "requestId": "%s"}' % (account_id, request_id),
    )

    put_audit_event(
        entity_id=account_id,
        event_type="MANUAL_ROTATION_TRIGGER",
        actor=owner_id_of(claims),
        outcome="STARTED",
        detail={"requestId": request_id, "executionArn": execution["executionArn"]},
    )

    return api_response(202, {"executionArn": execution["executionArn"], "requestId": request_id})


def handler(event, context):
    claims = get_claims(event)
    table = boto3.resource("dynamodb").Table(AD_TABLE_NAME)

    method = event.get("httpMethod")
    path_params = event.get("pathParameters") or {}
    account_id = path_params.get("accountId")
    resource_path = event.get("resource", "")

    if method == "GET" and account_id is None:
        return _list_accounts(table, claims, event.get("queryStringParameters"))
    if method == "GET" and account_id is not None:
        return _get_account(table, claims, account_id)
    if method == "POST" and resource_path.endswith("/rotate"):
        return _rotate_account(table, claims, account_id)

    return api_response(404, {"message": "not found"})
