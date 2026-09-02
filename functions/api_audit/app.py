"""api-audit-fn: GET /audit and GET /executions/{executionId}.

A non-admin may read the trail for their own actor id, for the shared team
partition, and for any certificate or account in the shared inventory — the
whole team owns those assets, so the audit trail for a shared cert has to be
readable by whoever clicked Renew on it. Anything else (another login's actor
id, a row owned by a different sub) still requires the Cognito admin group.
"""
import os
import traceback
from urllib.parse import unquote

import boto3
from crm_common import (
    SHARED_OWNER_ID,
    api_response,
    get_claims,
    guard_api_handler,
    is_admin,
    new_request_id,
    now_iso,
    can_view,
    owner_id_of,
    request_headers,
    request_origin,
    sanitize_event_for_logging,
    structured_log,
)

AUDIT_TABLE_NAME = os.environ["AUDIT_TABLE_NAME"]
# Read-only, and only to answer "is this entity id a shared team asset?" — see
# _is_shared_inventory_entity below.
CERT_TABLE_NAME = os.environ.get("CERT_TABLE_NAME", "")
IAM_TABLE_NAME = os.environ.get("IAM_TABLE_NAME", "")


def _is_shared_inventory_entity(entity_id, claims, request_id):
    """Whether `entity_id` names a certificate or account in the shared inventory.

    An audit EntityId is either an actor id (a Cognito sub) or the id of the
    resource acted on. The resource case is the one that matters here: renewal
    and rotation events hang off a CertId/AccountIdHash, so without this lookup
    the audit tab could only ever show a caller their own actor events and the
    "check the audit tab for details" the UI prints after a failed renewal was
    advice only an admin could act on.
    """
    lookups = (
        (CERT_TABLE_NAME, "CertId"),
        (IAM_TABLE_NAME, "AccountIdHash"),
    )
    dynamodb = boto3.resource("dynamodb")
    for table_name, key_name in lookups:
        if not table_name:
            continue
        try:
            item = dynamodb.Table(table_name).get_item(Key={key_name: entity_id}).get("Item")
        except Exception:
            # A denied or failing lookup must not turn a legitimate query into a
            # 500 — fall through and let the caller-scoping rule decide.
            structured_log(
                request_id, "shared_inventory_lookup_failed", level="WARN",
                function="api-audit", table=table_name, entityId=entity_id,
            )
            continue
        if item and can_view(item, claims):
            return True
    return False


def _get_audit(table, claims, query_params, request_id):
    query_params = query_params or {}
    entity_id = query_params.get("entityId")

    structured_log(
        request_id, "query_params", function="api-audit", table=AUDIT_TABLE_NAME,
        entityId=entity_id, fromTs=query_params.get("from"), toTs=query_params.get("to"),
    )

    if not entity_id:
        return api_response(400, {"message": "entityId is required"})
    allowed = (
        is_admin(claims)
        or entity_id == owner_id_of(claims)
        or entity_id == SHARED_OWNER_ID
        or _is_shared_inventory_entity(entity_id, claims, request_id)
    )
    if not allowed:
        # Not the caller's own actor id, not the shared team partition, and not a
        # shared inventory resource — a genuine cross-owner query, admin only.
        structured_log(
            request_id, "audit_forbidden", level="WARN", function="api-audit",
            entityId=entity_id,
        )
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
