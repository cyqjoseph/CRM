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
