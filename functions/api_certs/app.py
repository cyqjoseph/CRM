"""api-certs-fn: GET /certs, GET /certs/{certId}, POST /certs/{certId}/renew."""
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

CERT_TABLE_NAME = os.environ["CERT_TABLE_NAME"]
RENEWAL_STATE_MACHINE_ARN = os.environ["RENEWAL_STATE_MACHINE_ARN"]


def _list_certs(table, claims, query_params, request_id):
    query_params = query_params or {}
    if is_admin(claims) and query_params.get("ownerId"):
        owner_id = query_params["ownerId"]
    else:
        owner_id = owner_id_of(claims)

    structured_log(
        request_id, "query_params", function="api-certs", table=CERT_TABLE_NAME,
        action="query_all_certs", ownerId=owner_id, status=query_params.get("status"),
    )

    if not owner_id:
        # DynamoDB rejects an empty string for a key attribute, so an absent
        # `sub` would raise ValidationException here rather than return nothing —
        # another unhandled exception surfacing in the browser as a 502.
        structured_log(request_id, "unauthenticated", level="WARN", function="api-certs")
        return api_response(401, {"message": "unauthenticated"})

    try:
        response = table.query(
            IndexName="OwnerIndex",
            KeyConditionExpression="OwnerId = :owner",
            ExpressionAttributeValues={":owner": owner_id},
        )
    except Exception:
        structured_log(
            request_id, "dynamodb_error", level="ERROR", function="api-certs",
            table=CERT_TABLE_NAME, stackTrace=traceback.format_exc(),
        )
        raise

    items = response.get("Items", [])
    structured_log(
        request_id, "dynamodb_response", function="api-certs", table=CERT_TABLE_NAME,
        count=len(items), firstItem=items[0] if items else None,
    )

    if query_params.get("status"):
        items = [i for i in items if i.get("Status") == query_params["status"]]
    return api_response(200, {"items": items})


def _get_cert(table, claims, cert_id, request_id):
    structured_log(request_id, "query_params", function="api-certs", table=CERT_TABLE_NAME, certId=cert_id)
    try:
        response = table.get_item(Key={"CertId": cert_id})
    except Exception:
        structured_log(
            request_id, "dynamodb_error", level="ERROR", function="api-certs",
            table=CERT_TABLE_NAME, stackTrace=traceback.format_exc(),
        )
        raise
    item = response.get("Item")
    structured_log(request_id, "dynamodb_response", function="api-certs", table=CERT_TABLE_NAME, found=item is not None)
    if not item:
        return api_response(404, {"message": "not found"})
    if not is_admin(claims) and item.get("OwnerId") != owner_id_of(claims):
        return api_response(404, {"message": "not found"})
    return api_response(200, item)


def _renew_cert(table, claims, cert_id, request_id):
    structured_log(
        request_id, "renew_received", function="api-certs",
        certId=cert_id, stateMachineArn=RENEWAL_STATE_MACHINE_ARN,
    )

    response = table.get_item(Key={"CertId": cert_id})
    item = response.get("Item")
    structured_log(
        request_id, "renew_lookup", function="api-certs", table=CERT_TABLE_NAME,
        certId=cert_id, found=item is not None,
    )
    if not item:
        return api_response(404, {"message": "not found"})
    if not is_admin(claims) and item.get("OwnerId") != owner_id_of(claims):
        structured_log(
            request_id, "renew_forbidden", level="WARN", function="api-certs",
            certId=cert_id, ownerId=item.get("OwnerId"),
        )
        return api_response(404, {"message": "not found"})

    execution_input = '{"certId": "%s", "certArn": "%s", "requestId": "%s"}' % (
        cert_id, item.get("CertId", cert_id), request_id,
    )
    structured_log(
        request_id, "start_execution_attempt", function="api-certs",
        certId=cert_id, stateMachineArn=RENEWAL_STATE_MACHINE_ARN, input=execution_input,
    )

    try:
        sfn = boto3.client("stepfunctions")
        execution = sfn.start_execution(
            stateMachineArn=RENEWAL_STATE_MACHINE_ARN,
            name=request_id,
            input=execution_input,
        )
    except Exception as error:
        structured_log(
            request_id, "start_execution_error", level="ERROR", function="api-certs",
            statusCode=500, certId=cert_id, stateMachineArn=RENEWAL_STATE_MACHINE_ARN,
            error=str(error), errorType=type(error).__name__, stackTrace=traceback.format_exc(),
        )
        return api_response(500, {
            "error": "Step Functions call failed",
            "details": str(error),
            "certId": cert_id,
        })

    execution_arn = execution["executionArn"]
    execution_name = execution_arn.rsplit(":", 1)[-1]
    structured_log(
        request_id, "start_execution_response", function="api-certs",
        certId=cert_id, executionArn=execution_arn, executionName=execution_name,
    )

    put_audit_event(
        entity_id=cert_id,
        event_type="MANUAL_RENEWAL_TRIGGER",
        actor=owner_id_of(claims),
        outcome="STARTED",
        detail={"requestId": request_id, "executionArn": execution_arn},
    )

    response = api_response(202, {
        "executionArn": execution_arn,
        "executionName": execution_name,
        "certId": cert_id,
        "status": "RUNNING",
        "requestId": request_id,
    })
    structured_log(
        request_id, "renewal_started", function="api-certs", statusCode=202,
        certId=cert_id, executionArn=execution_arn, executionName=execution_name,
    )
    return response


@guard_api_handler
def handler(event, context):
    request_id = new_request_id()
    claims = get_claims(event)
    method = event.get("httpMethod")
    path_params = event.get("pathParameters") or {}
    cert_id = path_params.get("certId")
    resource_path = event.get("resource", "")

    structured_log(
        request_id, "start", function="api-certs", timestamp=now_iso(),
        table=CERT_TABLE_NAME, method=method, resource=resource_path,
        event=sanitize_event_for_logging(event), headers=request_headers(event),
        origin=request_origin(event),
    )

    table = boto3.resource("dynamodb").Table(CERT_TABLE_NAME)

    if method == "GET" and cert_id is None:
        response = _list_certs(table, claims, event.get("queryStringParameters"), request_id)
    elif method == "GET" and cert_id is not None:
        response = _get_cert(table, claims, cert_id, request_id)
    elif method == "POST" and resource_path.endswith("/renew"):
        response = _renew_cert(table, claims, cert_id, request_id)
    else:
        response = api_response(404, {"message": "not found"})

    structured_log(
        request_id, "returning_response", function="api-certs",
        statusCode=response["statusCode"], body=response["body"],
        corsHeaders=response.get("headers"),
    )
    return response
