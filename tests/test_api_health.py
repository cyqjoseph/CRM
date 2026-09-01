"""api-health-fn: GET /health, an unauthenticated connectivity probe.

Frontend 403s made it impossible to tell CORS/authorizer failures apart from
a dead Lambda/API Gateway wiring. This endpoint has no Cognito authorizer, so
a browser (or curl) can hit it to prove the CloudFront -> API Gateway ->
Lambda path itself works, independent of auth.
"""
import json

from conftest import load_module
from test_template import RESOURCES

app = load_module("api_health_app", "functions/api_health/app.py")


def test_health_returns_200_ok():
    response = app.handler({"httpMethod": "GET", "resource": "/health", "headers": {}}, None)
    assert response["statusCode"] == 200
    assert json.loads(response["body"]) == {"status": "ok"}


def test_health_response_carries_cors_headers():
    response = app.handler({"httpMethod": "GET", "resource": "/health", "headers": {}}, None)
    assert response["headers"]["Access-Control-Allow-Origin"]
    assert response["headers"]["Access-Control-Allow-Methods"]
    assert response["headers"]["Access-Control-Allow-Headers"]


def test_health_does_not_require_requestcontext_authorizer():
    """No Cognito claims at all — the route must not depend on them."""
    event = {"httpMethod": "GET", "resource": "/health", "headers": {"Origin": "https://example.com"}}
    response = app.handler(event, None)
    assert response["statusCode"] == 200


def test_health_route_has_no_authorizer_attached():
    for resource in RESOURCES.values():
        if resource.get("Type") != "AWS::Serverless::Function":
            continue
        for event in (resource.get("Properties", {}).get("Events") or {}).values():
            if event.get("Type") != "Api":
                continue
            props = event["Properties"]
            if props["Path"] == "/health" and props["Method"] == "get":
                assert props.get("Auth", {}).get("Authorizer") == "NONE", (
                    "/health must override the API's DefaultAuthorizer with "
                    "Auth.Authorizer: NONE, or a browser without a Cognito "
                    "session can never reach it to test connectivity"
                )
                return
    raise AssertionError("no GET /health route found in template.yaml")
