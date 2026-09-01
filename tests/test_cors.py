"""CORS coverage for the browser-facing API.

The UI is served from a CloudFront origin and calls API Gateway on a different
host, sending `Authorization: <idToken>`. A custom header makes every request
non-simple, so the browser issues a preflight `OPTIONS` first. Three separate
things all have to be right or the browser reports an opaque CORS failure and
never surfaces the real status:

1. The API must answer OPTIONS at all. Without `Cors` on AWS::Serverless::Api
   no OPTIONS method exists, and API Gateway answers 403 "Missing Authentication
   Token" with no CORS headers.
2. The preflight must NOT require authorization. SAM's
   `AddDefaultAuthorizerToCorsPreflight` defaults to TRUE, which attaches the
   Cognito authorizer to the generated OPTIONS method — but browsers never send
   Authorization on a preflight, so it 401s and CORS still fails.
3. Real responses need the header too. `Cors` only builds the OPTIONS mock; a
   Lambda proxy integration returns exactly the headers the function sets, and
   API-Gateway-generated 4XX/5XX (an authorizer 401, a 500) return only what the
   matching GatewayResponse defines.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "layers" / "common" / "python"))

from test_template import RESOURCES  # noqa: E402  (reuses the CFN-aware loader)

CORS_HEADER = "Access-Control-Allow-Origin"


# --- 1. the API answers OPTIONS -----------------------------------------------

def test_api_declares_cors():
    cors = RESOURCES["CrmApi"]["Properties"].get("Cors")
    assert cors, (
        "CrmApi has no Cors property, so SAM generates no OPTIONS method and "
        "every browser preflight gets 403 with no CORS headers"
    )
    assert "AllowOrigin" in cors
    # SAM injects these into an API Gateway mapping expression, so the value has
    # to be a quoted string literal, e.g. "'*'" — a bare * silently misbehaves.
    for key in ("AllowOrigin", "AllowHeaders", "AllowMethods"):
        value = cors[key]
        assert isinstance(value, str) and value.startswith("'") and value.endswith("'"), (
            f"Cors.{key} = {value!r} must be a single-quoted string literal"
        )


def test_cors_allows_the_headers_and_methods_the_ui_actually_sends():
    cors = RESOURCES["CrmApi"]["Properties"]["Cors"]
    headers = cors["AllowHeaders"].strip("'").lower()
    methods = cors["AllowMethods"].strip("'").upper()
    # ui/app.js sends Authorization on every call and Content-Type on POSTs.
    assert "authorization" in headers
    assert "content-type" in headers
    for method in ("GET", "POST", "OPTIONS"):
        assert method in methods, f"Cors.AllowMethods is missing {method}"


# --- 2. the preflight is unauthenticated --------------------------------------

def test_cors_preflight_does_not_require_the_cognito_authorizer():
    auth = RESOURCES["CrmApi"]["Properties"]["Auth"]
    assert auth.get("AddDefaultAuthorizerToCorsPreflight") is False, (
        "must be explicitly False — SAM defaults it to True, which puts the "
        "Cognito authorizer on the generated OPTIONS method, and a browser "
        "preflight carries no Authorization header so it 401s"
    )


# --- 3. real responses carry the header --------------------------------------

def test_lambda_responses_include_the_cors_header():
    from crm_common import api_response

    response = api_response(200, {"items": []})
    assert CORS_HEADER in response["headers"], (
        "api_response must set Access-Control-Allow-Origin; a Lambda proxy "
        "integration returns only the headers the function sets, and Cors on the "
        "API only covers the OPTIONS preflight"
    )
    # Body must stay valid JSON — the UI does response.json() unconditionally.
    assert json.loads(response["body"]) == {"items": []}


def test_lambda_responses_include_allow_methods_and_allow_headers():
    """Diagnostic hardening: every real response, not just the OPTIONS mock
    Cors generates, carries the same allow-list so a proxy/cache stripping the
    preflight response doesn't leave the real GET/POST response looking
    unconfigured in browser devtools."""
    from crm_common import api_response

    response = api_response(200, {"items": []})
    methods = response["headers"]["Access-Control-Allow-Methods"]
    headers = response["headers"]["Access-Control-Allow-Headers"]
    for method in ("GET", "POST", "OPTIONS"):
        assert method in methods
    assert "content-type" in headers.lower()
    assert "authorization" in headers.lower()


@pytest.mark.parametrize("status", [200, 202, 404])
def test_cors_header_present_on_every_status_the_api_returns(status):
    from crm_common import api_response

    assert CORS_HEADER in api_response(status, {"message": "x"})["headers"]


def test_gateway_responses_add_cors_to_api_gateway_generated_errors():
    """An authorizer 401 never reaches the Lambda, so only a GatewayResponse can
    attach CORS headers to it. Without these, an expired token shows up in the
    browser as a CORS error rather than a readable 401."""
    gateway_responses = {
        logical_id: resource
        for logical_id, resource in RESOURCES.items()
        if resource.get("Type") == "AWS::ApiGateway::GatewayResponse"
    }
    covered = {
        r["Properties"]["ResponseType"] for r in gateway_responses.values()
    }
    assert {"DEFAULT_4XX", "DEFAULT_5XX"} <= covered, (
        f"missing GatewayResponse coverage; found {sorted(covered)}"
    )

    for logical_id, resource in gateway_responses.items():
        params = resource["Properties"]["ResponseParameters"]
        key = f"gatewayresponse.header.{CORS_HEADER}"
        assert key in params, f"{logical_id} does not set {CORS_HEADER}"
        value = params[key]
        assert isinstance(value, str) and value.startswith("'") and value.endswith("'"), (
            f"{logical_id}.{key} = {value!r} must be a single-quoted literal"
        )
        assert resource["Properties"]["RestApiId"] == {"Fn::Ref": "CrmApi"}
