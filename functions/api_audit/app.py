"""api-audit-fn: GET /audit and GET /executions/{executionId}.

Cross-owner audit queries (no entityId scoping to the caller) require the
caller to be in the Cognito admin group.
"""
import os
import traceback
from urllib.parse import unquote

import boto3
from crm_common import (
    api_response,
    get_claims,
    guard_api_handler,
    is_admin,
    new_request_id,
    now_iso,
    owner_id_of,
    request_headers,
    request_origin,
    sanitize_event_for_logging,
    structured_log,
)

AUDIT_TABLE_NAME = os.environ["AUDIT_TABLE_NAME"]


def _get_audit(table, claims, query_params, request_id):
    query_params = query_params or {}
    entity_id = query_params.get("entityId")

    structured_log(
        request_id, "query_params", function="api-audit", table=AUDIT_TABLE_NAME,
        entityId=entity_id, fromTs=query_params.get("from"), toTs=query_params.get("to"),
    )

    if not entity_id:
        return api_response(400, {"message": "entityId is required"})
    if entity_id != owner_id_of(claims) and not is_admin(claims):
        # A non-admin may only look up their own actor id; anything else is
        # a cross-owner query and requires the admin group.
        return api_response(403, {"message": "forbidden"})

    key_condition = "EntityId = :entityId"
    values = {":entityId": entity_id}
    if query_params.get("from") and query_params.get("to"):
        # from/to are ISO-8601 strings, matching EventTimestamp's stored type.
        key_condition += " AND EventTimestamp BETWEEN :from AND :to"
        values[":from"] = query_params["from"]
        values[":to"] = query_params["to"]

    try:
        response = table.query(
            KeyConditionExpression=key_condition,
            ExpressionAttributeValues=values,
        )
    except Exception:
        structured_log(
            request_id, "dynamodb_error", level="ERROR", function="api-audit",
            table=AUDIT_TABLE_NAME, stackTrace=traceback.format_exc(),
        )
        raise

    items = response.get("Items", [])
    structured_log(
        request_id, "dynamodb_response", function="api-audit", table=AUDIT_TABLE_NAME,
        count=len(items), firstItem=items[0] if items else None,
    )
    return api_response(200, {"items": items})


# An execution ARN is the path parameter here, and it is full of colons. The
# browser must percent-encode them, and API Gateway REST APIs hand the parameter
# to Lambda STILL ENCODED — `pathParameters` arrives as
# "arn%3Aaws%3Astates%3A..." rather than "arn:aws:states:...". Passing that
# straight to DescribeExecution fails with
# `InvalidArn: Invalid ARN prefix: arn%3Aaws%3A...`, which reads like a bad ARN
# from the caller rather than an un-decoded one.
EXECUTION_ARN_PREFIX = "arn:aws:states:"


def _decode_execution_arn(raw):
    """Percent-decode the path parameter. A no-op on an already-decoded ARN,
    since a well-formed ARN contains no '%'."""
    return unquote(raw) if raw else raw


def _get_execution(claims, execution_id, request_id):
    execution_id = _decode_execution_arn(execution_id)
    structured_log(request_id, "describe_execution_attempt", function="api-audit", executionArn=execution_id)

    # Reject a malformed ARN here with a 400 rather than letting botocore raise
    # and reporting the caller's own bad input as a server error.
    if not execution_id or not execution_id.startswith(EXECUTION_ARN_PREFIX):
        structured_log(
            request_id, "describe_execution_bad_arn", level="WARN", function="api-audit",
            executionArn=execution_id,
        )
        return api_response(400, {
            "error": "not a Step Functions execution ARN",
            "details": f"expected a value starting with {EXECUTION_ARN_PREFIX!r}",
            "executionArn": execution_id,
        })

    sfn = boto3.client("stepfunctions")
    try:
        response = sfn.describe_execution(executionArn=execution_id)
    except Exception as error:
        structured_log(
            request_id, "describe_execution_error", level="ERROR", function="api-audit",
            statusCode=500, executionArn=execution_id, error=str(error),
            errorType=type(error).__name__, stackTrace=traceback.format_exc(),
        )
        return api_response(500, {
            "error": "DescribeExecution call failed",
            "details": str(error),
            "executionArn": execution_id,
        })
    structured_log(
        request_id, "describe_execution_response", function="api-audit",
        executionArn=execution_id, status=response["status"],
    )

    events = []
    if response["status"] != "RUNNING":
        # Only worth the extra call once the execution has settled — history
        # is what tells us *which* state failed, beyond the terminal status.
        try:
            history = sfn.get_execution_history(
                executionArn=execution_id, maxResults=20, reverseOrder=True,
            )
            events = [
                {"type": e["type"], "timestamp": e["timestamp"].isoformat(), "id": e["id"]}
                for e in history.get("events", [])
            ]
        except Exception as error:
            structured_log(
                request_id, "get_execution_history_error", level="ERROR", function="api-audit",
                executionArn=execution_id, error=str(error), stackTrace=traceback.format_exc(),
            )

    return api_response(
        200,
        {
            "status": response["status"],
            "output": response.get("output"),
            "events": events,
        },
    )


@guard_api_handler
def handler(event, context):
    request_id = new_request_id()
    claims = get_claims(event)
    resource_path = event.get("resource", "")
    path_params = event.get("pathParameters") or {}

    structured_log(
        request_id, "start", function="api-audit", timestamp=now_iso(),
        table=AUDIT_TABLE_NAME, method=event.get("httpMethod"), resource=resource_path,
        event=sanitize_event_for_logging(event), headers=request_headers(event),
        origin=request_origin(event),
    )

    if resource_path.startswith("/executions/"):
        response = _get_execution(claims, path_params.get("executionId"), request_id)
    else:
        table = boto3.resource("dynamodb").Table(AUDIT_TABLE_NAME)
        response = _get_audit(table, claims, event.get("queryStringParameters"), request_id)

    structured_log(
        request_id, "returning_response", function="api-audit",
        statusCode=response["statusCode"], body=response["body"],
        corsHeaders=response.get("headers"),
    )
    return response
