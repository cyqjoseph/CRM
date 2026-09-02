"""api-executions-fn: GET /executions/{executionId}.

Reports the terminal state of one Step Functions execution, so the UI's Renew and
Rotate buttons can say whether the work actually succeeded. Both return 202 the
instant the state machine starts, which on its own says nothing about the outcome.

This function used to also serve GET /audit, a search over the audit table by
entity id. That route is gone: it was only ever usable if you already knew a
certificate's exact id (a prefix like "demo-cert" matched nothing and, being
unresolvable, was refused as a cross-owner lookup), so in practice it answered
403 to every search anyone actually typed. The audit trail itself is unchanged —
the state machines and crm_common.put_audit_event still write every action to
app-d9fae51c-1929cc69-audit-hot, and audit-exporter-fn still archives it to S3.
Only the search UI is withdrawn.
"""
import traceback
from urllib.parse import unquote

import boto3
from crm_common import (
    api_response,
    get_claims,
    guard_api_handler,
    new_request_id,
    now_iso,
    request_headers,
    request_origin,
    sanitize_event_for_logging,
    structured_log,
)

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
    structured_log(request_id, "describe_execution_attempt", function="api-executions", executionArn=execution_id)

    # Reject a malformed ARN here with a 400 rather than letting botocore raise
    # and reporting the caller's own bad input as a server error.
    if not execution_id or not execution_id.startswith(EXECUTION_ARN_PREFIX):
        structured_log(
            request_id, "describe_execution_bad_arn", level="WARN", function="api-executions",
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
            request_id, "describe_execution_error", level="ERROR", function="api-executions",
            statusCode=500, executionArn=execution_id, error=str(error),
            errorType=type(error).__name__, stackTrace=traceback.format_exc(),
        )
        return api_response(500, {
            "error": "DescribeExecution call failed",
            "details": str(error),
            "executionArn": execution_id,
        })
    structured_log(
        request_id, "describe_execution_response", function="api-executions",
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
                request_id, "get_execution_history_error", level="ERROR", function="api-executions",
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
        request_id, "start", function="api-executions", timestamp=now_iso(),
        method=event.get("httpMethod"), resource=resource_path,
        event=sanitize_event_for_logging(event), headers=request_headers(event),
        origin=request_origin(event),
    )

    if resource_path.startswith("/executions/"):
        response = _get_execution(claims, path_params.get("executionId"), request_id)
    else:
        response = api_response(404, {"message": "not found"})

    structured_log(
        request_id, "returning_response", function="api-executions",
        statusCode=response["statusCode"], body=response["body"],
        corsHeaders=response.get("headers"),
    )
    return response
