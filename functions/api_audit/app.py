"""api-audit-fn: GET /audit and GET /executions/{executionId}.

Cross-owner audit queries (no entityId scoping to the caller) require the
caller to be in the Cognito admin group.
"""
import os

import boto3
from crm_common import api_response, get_claims, is_admin, owner_id_of

AUDIT_TABLE_NAME = os.environ["AUDIT_TABLE_NAME"]


def _get_audit(table, claims, query_params):
    query_params = query_params or {}
    entity_id = query_params.get("entityId")

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

    response = table.query(
        KeyConditionExpression=key_condition,
        ExpressionAttributeValues=values,
    )
    return api_response(200, {"items": response.get("Items", [])})


def _get_execution(claims, execution_id):
    sfn = boto3.client("stepfunctions")
    # execution_id is passed to the API as the executionArn returned by the
    # renew/rotate endpoints.
    response = sfn.describe_execution(executionArn=execution_id)
    return api_response(
        200,
        {
            "status": response["status"],
            "output": response.get("output"),
        },
    )


def handler(event, context):
    claims = get_claims(event)
    resource_path = event.get("resource", "")
    path_params = event.get("pathParameters") or {}

    if resource_path.startswith("/executions/"):
        return _get_execution(claims, path_params.get("executionId"))

    table = boto3.resource("dynamodb").Table(AUDIT_TABLE_NAME)
    return _get_audit(table, claims, event.get("queryStringParameters"))
