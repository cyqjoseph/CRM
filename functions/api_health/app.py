"""api-health-fn: GET /health — unauthenticated connectivity probe.

No Cognito authorizer is attached to this route (see template.yaml's
ApiHealthFunction Events.HealthCheck.Auth). It exists purely so a browser (or
curl) can confirm CloudFront/API Gateway/Lambda are wired up correctly,
independent of whether a 403 elsewhere is CORS, the authorizer, or a dead
integration.
"""
from crm_common import (
    api_response,
    guard_api_handler,
    new_request_id,
    now_iso,
    request_headers,
    request_origin,
    sanitize_event_for_logging,
    structured_log,
)


@guard_api_handler
def handler(event, context):
    request_id = new_request_id()

    structured_log(
        request_id, "start", function="api-health", timestamp=now_iso(),
        method=(event or {}).get("httpMethod"), resource=(event or {}).get("resource"),
        event=sanitize_event_for_logging(event), headers=request_headers(event),
        origin=request_origin(event),
    )

    response = api_response(200, {"status": "ok"})

    structured_log(
        request_id, "returning_response", function="api-health",
        statusCode=response["statusCode"], body=response["body"],
        corsHeaders=response.get("headers"),
    )
    return response
