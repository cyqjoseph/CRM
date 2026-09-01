import json

from conftest import load_module

crm_common = load_module("crm_common_test_target", "layers/common/python/crm_common/__init__.py")


def test_structured_log_emits_one_json_line_with_request_id_and_event_type(capsys):
    crm_common.structured_log("req-123", "DISCOVERY_START", source="acm", count=3)

    out = capsys.readouterr().out.strip()
    record = json.loads(out)

    assert record["requestId"] == "req-123"
    assert record["eventType"] == "DISCOVERY_START"
    assert record["level"] == "INFO"
    assert record["source"] == "acm"
    assert record["count"] == 3


def test_structured_log_accepts_a_custom_level():
    crm_common.structured_log("req-456", "DISCOVERY_FAILED", level="ERROR")
    # No assertion needed beyond "doesn't raise" — level is caller-controlled.


def test_request_headers_redacts_authorization():
    """Authorization carries the caller's live Cognito ID token. Logging it
    verbatim to CloudWatch would let anyone with log read access replay it."""
    event = {"headers": {"Authorization": "eyJraWQ.secret.token", "Origin": "https://example.com"}}

    headers = crm_common.request_headers(event)

    assert headers["Authorization"] == "***redacted***"
    assert headers["Origin"] == "https://example.com"


def test_request_headers_is_case_insensitive_and_handles_missing_headers():
    assert crm_common.request_headers({"headers": {"authorization": "secret"}})["authorization"] == "***redacted***"
    assert crm_common.request_headers({}) == {}
    assert crm_common.request_headers({"headers": None}) == {}


def test_request_origin_reads_either_case():
    assert crm_common.request_origin({"headers": {"Origin": "https://a.example.com"}}) == "https://a.example.com"
    assert crm_common.request_origin({"headers": {"origin": "https://b.example.com"}}) == "https://b.example.com"
    assert crm_common.request_origin({"headers": {}}) is None


def test_sanitize_event_for_logging_redacts_authorization_but_keeps_the_rest():
    event = {
        "httpMethod": "GET",
        "resource": "/certs",
        "headers": {"Authorization": "eyJraWQ.secret.token", "Origin": "https://example.com"},
    }

    sanitized = crm_common.sanitize_event_for_logging(event)

    assert sanitized["httpMethod"] == "GET"
    assert sanitized["resource"] == "/certs"
    assert sanitized["headers"]["Authorization"] == "***redacted***"
    assert sanitized["headers"]["Origin"] == "https://example.com"
    # Must not mutate the caller's event in place.
    assert event["headers"]["Authorization"] == "eyJraWQ.secret.token"
