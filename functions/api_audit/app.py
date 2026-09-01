"""api-audit-fn: GET /audit and GET /executions/{executionId}.

Cross-owner audit queries (no entityId scoping to the caller) require the
caller to be in the Cognito admin group.
"""
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


def _get_execution(claims, execution_id, request_id):
    structured_log(request_id, "query_params", function="api-audit", executionArn=execution_id)
    sfn = boto3.client("stepfunctions")
    # execution_id is passed to the API as the executionArn returned by the
    # renew/rotate endpoints.
    try:
        response = sfn.describe_execution(executionArn=execution_id)
    except Exception:
        structured_log(
            request_id, "stepfunctions_error", level="ERROR", function="api-audit",
            executionArn=execution_id, stackTrace=traceback.format_exc(),
        )
        raise
    structured_log(request_id, "stepfunctions_response", function="api-audit", status=response["status"])
    return api_response(
        200,
        {
            "status": response["status"],
            "output": response.get("output"),
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
    )

    if resource_path.startswith("/executions/"):
        response = _get_execution(claims, path_params.get("executionId"), request_id)
    else:
        table = boto3.resource("dynamodb").Table(AUDIT_TABLE_NAME)
        response = _get_audit(table, claims, event.get("queryStringParameters"), request_id)

    structured_log(
        request_id, "returning_response", function="api-audit",
        statusCode=response["statusCode"], body=response["body"],
    )
    return response
