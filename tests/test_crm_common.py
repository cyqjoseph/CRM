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


# --- Shared ownership --------------------------------------------------------
#
# OwnerId is OwnerIndex's HASH key, so its value is the whole access-control
# story for an inventory row. These pin down the rule that made three team
# members see three different dashboards: a row owned by one Cognito sub is
# invisible to every other login.


def test_shared_partition_is_visible_to_every_login():
    for claims in ({"sub": "sub-a"}, {"sub": "sub-b"}, {"sub": "sub-c"}):
        assert crm_common.SHARED_OWNER_ID in crm_common.visible_owner_ids(claims)


def test_visible_owner_ids_puts_the_shared_partition_first_then_the_callers_own():
    assert crm_common.visible_owner_ids({"sub": "sub-a"}) == [crm_common.SHARED_OWNER_ID, "sub-a"]


def test_visible_owner_ids_never_repeats_the_shared_partition():
    """A caller whose sub somehow equals the shared id must not be queried twice."""
    claims = {"sub": crm_common.SHARED_OWNER_ID}
    assert crm_common.visible_owner_ids(claims) == [crm_common.SHARED_OWNER_ID]


def test_can_view_a_shared_row_regardless_of_which_login_asks():
    row = {"OwnerId": crm_common.SHARED_OWNER_ID}
    assert crm_common.can_view(row, {"sub": "sub-a"})
    assert crm_common.can_view(row, {"sub": "sub-b"})


def test_can_view_still_covers_a_row_left_owned_by_the_callers_own_sub():
    assert crm_common.can_view({"OwnerId": "sub-a"}, {"sub": "sub-a"})


def test_can_view_rejects_a_row_owned_by_a_different_login():
    assert not crm_common.can_view({"OwnerId": "sub-b"}, {"sub": "sub-a"})


def test_admins_can_view_anything():
    claims = {"sub": "sub-a", "cognito:groups": "admins"}
    assert crm_common.can_view({"OwnerId": "sub-b"}, claims)


# --- Partition union query ---------------------------------------------------


def _table_returning(pages_by_owner):
    """A table stub whose query() answers per requested OwnerId."""
    from unittest.mock import MagicMock

    table = MagicMock()

    def query(**kwargs):
        owner = kwargs["ExpressionAttributeValues"][":owner"]
        pages = pages_by_owner.get(owner, [{"Items": []}])
        index = getattr(query, "_calls", {}).get(owner, 0)
        query._calls = getattr(query, "_calls", {})
        query._calls[owner] = index + 1
        return pages[min(index, len(pages) - 1)]

    table.query.side_effect = query
    return table


def test_query_owner_partitions_merges_the_shared_and_own_partitions():
    table = _table_returning({
        crm_common.SHARED_OWNER_ID: [{"Items": [{"CertId": "shared-1"}]}],
        "sub-a": [{"Items": [{"CertId": "own-1"}]}],
    })

    items = crm_common.query_owner_partitions(table, "OwnerIndex", "CertId", {"sub": "sub-a"})

    assert {i["CertId"] for i in items} == {"shared-1", "own-1"}
    assert table.query.call_count == 2


def test_query_owner_partitions_deduplicates_a_row_present_in_both_partitions():
    """Mid-migration the same CertId can sit in both partitions; the UI must not
    render it twice."""
    table = _table_returning({
        crm_common.SHARED_OWNER_ID: [{"Items": [{"CertId": "cert-1", "OwnerId": crm_common.SHARED_OWNER_ID}]}],
        "sub-a": [{"Items": [{"CertId": "cert-1", "OwnerId": "sub-a"}]}],
    })

    items = crm_common.query_owner_partitions(table, "OwnerIndex", "CertId", {"sub": "sub-a"})

    assert len(items) == 1
    # The shared partition is queried first, so its copy is the one kept.
    assert items[0]["OwnerId"] == crm_common.SHARED_OWNER_ID


def test_query_owner_partitions_follows_pagination():
    """A partition holding more than 1MB of rows answers in pages; stopping at
    the first one silently truncates the dashboard."""
    table = _table_returning({
        crm_common.SHARED_OWNER_ID: [
            {"Items": [{"CertId": "a"}], "LastEvaluatedKey": {"CertId": "a"}},
            {"Items": [{"CertId": "b"}]},
        ],
    })

    items = crm_common.query_owner_partitions(table, "OwnerIndex", "CertId", {"sub": crm_common.SHARED_OWNER_ID})

    assert {i["CertId"] for i in items} == {"a", "b"}


def test_query_owner_partitions_honours_an_admin_owner_override():
    table = _table_returning({"someone-else": [{"Items": [{"CertId": "theirs"}]}]})

    items = crm_common.query_owner_partitions(
        table, "OwnerIndex", "CertId", {"sub": "sub-a"}, owner_id_override="someone-else"
    )

    assert [i["CertId"] for i in items] == ["theirs"]
    assert table.query.call_count == 1


# --- Certificate status vocabulary ------------------------------------------


def test_cert_status_agrees_with_the_expiry_date():
    from datetime import datetime, timedelta, timezone

    now = datetime(2026, 9, 2, tzinfo=timezone.utc)
    assert crm_common.cert_status_for(now - timedelta(days=1), now) == crm_common.CERT_STATUS_EXPIRED
    assert crm_common.cert_status_for(now + timedelta(days=1), now) == crm_common.CERT_STATUS_ISSUED


def test_cert_status_accepts_an_iso_string_and_assumes_utc_when_naive():
    from datetime import datetime, timezone

    now = datetime(2026, 9, 2, tzinfo=timezone.utc)
    assert crm_common.cert_status_for("2026-09-01", now) == crm_common.CERT_STATUS_EXPIRED
    assert crm_common.cert_status_for("2026-09-03T00:00:00+00:00", now) == crm_common.CERT_STATUS_ISSUED


def test_issued_is_the_literal_expiry_alerting_queries():
    """expiry-evaluator-fn queries ExpiryIndex with Status = "ISSUED"; any drift
    here silently removes every cert from alerting."""
    assert crm_common.CERT_STATUS_ISSUED == "ISSUED"
