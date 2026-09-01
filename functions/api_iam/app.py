"""api-iam-fn: GET /iam/accounts, GET /iam/accounts/{accountId}, POST /iam/accounts/{accountId}/rotate."""
import json
import os
import traceback

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
    request_headers,
    request_origin,
    sanitize_event_for_logging,
    structured_log,
)

IAM_TABLE_NAME = os.environ["IAM_TABLE_NAME"]
ROTATION_STATE_MACHINE_ARN = os.environ["ROTATION_STATE_MACHINE_ARN"]


def _list_accounts(table, claims, query_params, request_id):
    query_params = query_params or {}
    if is_admin(claims) and query_params.get("ownerId"):
        owner_id = query_params["ownerId"]
    else:
        owner_id = owner_id_of(claims)

    structured_log(
        request_id, "query_params", function="api-iam", table=IAM_TABLE_NAME,
        action="query_all_accounts", ownerId=owner_id, status=query_params.get("status"),
    )

    if not owner_id:
        # An empty string is not a valid DynamoDB key value; without this the
        # query raises ValidationException and API Gateway reports a 502.
        structured_log(request_id, "unauthenticated", level="WARN", function="api-iam")
        return api_response(401, {"message": "unauthenticated"})

    try:
        response = table.query(
            IndexName="OwnerIndex",
            KeyConditionExpression="OwnerId = :owner",
            ExpressionAttributeValues={":owner": owner_id},
        )
    except Exception:
        structured_log(
            request_id, "dynamodb_error", level="ERROR", function="api-iam",
            table=IAM_TABLE_NAME, stackTrace=traceback.format_exc(),
        )
        raise

    items = response.get("Items", [])
    structured_log(
        request_id, "dynamodb_response", function="api-iam", table=IAM_TABLE_NAME,
        count=len(items), firstItem=items[0] if items else None,
    )

    if query_params.get("status"):
        items = [i for i in items if i.get("Status") == query_params["status"]]
    return api_response(200, {"items": items})


def _get_account(table, claims, account_id, request_id):
    structured_log(request_id, "query_params", function="api-iam", table=IAM_TABLE_NAME, accountId=account_id)
    try:
        response = table.get_item(Key={"AccountIdHash": account_id})
    except Exception:
        structured_log(
            request_id, "dynamodb_error", level="ERROR", function="api-iam",
            table=IAM_TABLE_NAME, stackTrace=traceback.format_exc(),
        )
        raise
    item = response.get("Item")
    structured_log(request_id, "dynamodb_response", function="api-iam", table=IAM_TABLE_NAME, found=item is not None)
    if not item:
        return api_response(404, {"message": "not found"})
    if not is_admin(claims) and item.get("OwnerId") != owner_id_of(claims):
        return api_response(404, {"message": "not found"})
    return api_response(200, item)


def _rotate_account(table, claims, account_id, request_id):
    structured_log(request_id, "query_params", function="api-iam", table=IAM_TABLE_NAME, accountId=account_id, action="rotate")
    response = table.get_item(Key={"AccountIdHash": account_id})
    item = response.get("Item")
    if not item:
        return api_response(404, {"message": "not found"})
    if not is_admin(claims) and item.get("OwnerId") != owner_id_of(claims):
        return api_response(404, {"message": "not found"})

    # Same isolated try/except as api-certs-fn's renew path: a StartExecution
    # failure returns the exception message (e.g. an AccessDeniedException naming
    # the missing action) rather than guard_api_handler's generic "internal
    # error", which is otherwise indistinguishable in the browser from a 403.
    try:
        sfn = boto3.client("stepfunctions")
        execution = sfn.start_execution(
            stateMachineArn=ROTATION_STATE_MACHINE_ARN,
            name=request_id,
            input=json.dumps({"accountIdHash": account_id, "requestId": request_id}),
        )
    except Exception as error:
        structured_log(
            request_id, "start_execution_error", level="ERROR", function="api-iam",
            statusCode=500, accountId=account_id, stateMachineArn=ROTATION_STATE_MACHINE_ARN,
            error=str(error), errorType=type(error).__name__, stackTrace=traceback.format_exc(),
        )
        return api_response(500, {
            "error": "Step Functions call failed",
            "details": str(error),
            "accountId": account_id,
        })

    put_audit_event(
        entity_id=account_id,
        event_type="MANUAL_ROTATION_TRIGGER",
        actor=owner_id_of(claims),
        outcome="STARTED",
        detail={"requestId": request_id, "executionArn": execution["executionArn"]},
    )

    structured_log(
        request_id, "rotation_started", function="api-iam",
        accountId=account_id, executionArn=execution["executionArn"],
    )
    return api_response(202, {
        "executionArn": execution["executionArn"],
        "accountId": account_id,
        "status": "RUNNING",
        "requestId": request_id,
    })


@guard_api_handler
def handler(event, context):
    request_id = new_request_id()
    claims = get_claims(event)
    method = event.get("httpMethod")
    path_params = event.get("pathParameters") or {}
    account_id = path_params.get("accountId")
    resource_path = event.get("resource", "")

    structured_log(
        request_id, "start", function="api-iam", timestamp=now_iso(),
        table=IAM_TABLE_NAME, method=method, resource=resource_path,
        event=sanitize_event_for_logging(event), headers=request_headers(event),
        origin=request_origin(event),
    )

    table = boto3.resource("dynamodb").Table(IAM_TABLE_NAME)

    if method == "GET" and account_id is None:
        response = _list_accounts(table, claims, event.get("queryStringParameters"), request_id)
    elif method == "GET" and account_id is not None:
        response = _get_account(table, claims, account_id, request_id)
    elif method == "POST" and resource_path.endswith("/rotate"):
        response = _rotate_account(table, claims, account_id, request_id)
    else:
        response = api_response(404, {"message": "not found"})

    structured_log(
        request_id, "returning_response", function="api-iam",
        statusCode=response["statusCode"], body=response["body"],
        corsHeaders=response.get("headers"),
    )
    return response
