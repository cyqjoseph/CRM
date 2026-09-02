"""scripts/gen_demo_data.py: demo inventory generation.

The traps this pins down are all silent ones — DynamoDB accepts every mistake
below and simply returns fewer rows than expected:

  - A row missing the GSI's RANGE key (ExpiryDate / NextRotationDate) is written
    successfully and then omitted from the index entirely, so GET /certs never
    returns it.
  - `OwnerId` is OwnerIndex's HASH key, so its value decides which logins can see
    the row. Seeding it with one Cognito sub gave that member a private dashboard
    and showed every other member nothing; rows go to the shared team partition.
  - `Status` is the HASH key of ExpiryIndex/StatusIndex and expiry-evaluator-fn
    queries those with the literals "ISSUED" and "active". Any other value is
    invisible to the alerting path.
  - A `Status` picked independently of `ExpiryDate` produces rows reading
    "ISSUED" that expired months ago, and an inventory that can never show a
    single expired certificate.
  - BatchWriteItem's 25-item cap is per REQUEST, across all tables in the
    payload, not per table. Exceeding it fails the whole call.
"""
import json
import random
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from conftest import load_module  # noqa: E402

import gen_demo_data as gen  # noqa: E402

OWNER = gen.SHARED_OWNER_ID


def _rng():
    return random.Random(0)


# --- Certificates ------------------------------------------------------------


def test_every_cert_carries_both_index_keys_and_the_owner():
    for item in gen.build_certs(OWNER, 40, _rng()):
        assert item["OwnerId"]["S"] == OWNER, "OwnerIndex HASH key"
        assert item["ExpiryDate"]["S"], "OwnerIndex + ExpiryIndex RANGE key"
        assert item["Status"]["S"], "ExpiryIndex HASH key"
        assert item["CertId"]["S"].startswith(gen.DEMO_PREFIX)


def test_cert_ids_are_unique():
    items = gen.build_certs(OWNER, 200, _rng())
    ids = [i["CertId"]["S"] for i in items]
    assert len(set(ids)) == len(ids)


def test_cert_domains_are_unique_so_rows_are_distinguishable_in_the_ui():
    """SERVICES wraps around past 20 rows; a repeated hostname makes the table
    look duplicated even though the ids differ."""
    items = gen.build_certs(OWNER, 200, _rng())
    domains = [i["Domain"]["S"] for i in items]
    assert len(set(domains)) == len(domains)


def _days_left(item):
    from datetime import date

    return (date.fromisoformat(item["ExpiryDate"]["S"]) - date.today()).days


def test_expiry_dates_cover_every_band_including_already_expired():
    """Seeding must exercise the UI's rendering, not just its query: expired,
    <=7d red, <=30d amber, beyond green."""
    items = gen.build_certs(OWNER, 16, _rng())
    days = [_days_left(i) for i in items]
    assert any(d < 0 for d in days), f"no expired cert: {days}"
    assert any(0 <= d <= 7 for d in days), f"no red-band cert: {days}"
    assert any(7 < d <= 30 for d in days), f"no amber-band cert: {days}"
    assert any(d > 30 for d in days), f"no green-band cert: {days}"


def test_every_date_is_relative_to_today_so_a_seed_can_never_age():
    """A hardcoded date silently ages into the past and renders every row as long
    expired — the bug the original fixed seed had. Every date must stay inside the
    window the bands describe, measured from today."""
    lowest = min(low for _, low, _ in gen.BANDS)
    highest = max(high for _, _, high in gen.BANDS)
    for item in gen.build_certs(OWNER, 40, _rng()):
        assert lowest <= _days_left(item) <= highest


def test_status_always_agrees_with_the_expiry_date():
    """The reported inconsistency: rows reading "ISSUED" that expire tomorrow, and
    a status picked at random independently of the date."""
    for item in gen.build_certs(OWNER, 80, _rng()):
        days = _days_left(item)
        status = item["Status"]["S"]
        if days < 0:
            assert status == gen.CERT_EXPIRED_STATUS, f"{item['CertId']['S']} expired {days}d ago but reads {status}"
        else:
            assert status != gen.CERT_EXPIRED_STATUS, f"{item['CertId']['S']} expires in {days}d but reads EXPIRED"


def test_no_certificate_awaiting_validation_is_also_about_to_expire():
    """PENDING_VALIDATION means not yet issued, so it cannot be days from expiry."""
    for item in gen.build_certs(OWNER, 80, _rng()):
        if item["Status"]["S"] == gen.CERT_PENDING_STATUS:
            assert _days_left(item) > 30, item["CertId"]["S"]


def test_most_certs_are_alertable_but_some_deliberately_are_not():
    items = gen.build_certs(OWNER, 60, _rng())
    statuses = [i["Status"]["S"] for i in items]
    alertable = statuses.count(gen.CERT_ALERTABLE_STATUS)
    assert alertable > len(statuses) / 2, "most rows must be queryable by ExpiryIndex"
    assert alertable < len(statuses), "some rows must be excluded, to prove the filter works"


def test_every_non_alertable_status_is_actually_represented():
    statuses = {i["Status"]["S"] for i in gen.build_certs(OWNER, 80, _rng())}
    for status in gen.CERT_OTHER_STATUSES:
        assert status in statuses, f"{status} never generated — the UI never renders it"


def test_the_status_literals_match_the_ones_every_lambda_uses():
    """gen_demo_data.py duplicates these rather than importing crm_common (it is
    stdlib-only by design), so the copies have to be checked against the source."""
    crm_common = load_module("crm_common_for_gen", "layers/common/python/crm_common/__init__.py")
    assert gen.CERT_ALERTABLE_STATUS == crm_common.CERT_STATUS_ISSUED
    assert gen.CERT_EXPIRED_STATUS == crm_common.CERT_STATUS_EXPIRED
    assert gen.CERT_REVOKED_STATUS == crm_common.CERT_STATUS_REVOKED
    assert gen.CERT_PENDING_STATUS == crm_common.CERT_STATUS_PENDING_VALIDATION


def test_the_default_owner_is_the_shared_partition_every_login_can_read():
    crm_common = load_module("crm_common_for_gen_owner", "layers/common/python/crm_common/__init__.py")
    assert gen.SHARED_OWNER_ID == crm_common.SHARED_OWNER_ID
    for item in gen.build_certs(gen.SHARED_OWNER_ID, 5, _rng()):
        assert item["OwnerId"]["S"] == crm_common.SHARED_OWNER_ID


# --- IAM accounts ------------------------------------------------------------


def test_every_account_carries_both_index_keys_and_the_ui_columns():
    for item in gen.build_accounts(OWNER, 15, _rng()):
        assert item["OwnerId"]["S"] == OWNER
        assert item["NextRotationDate"]["S"], "OwnerIndex + StatusIndex RANGE key"
        assert item["Status"]["S"], "StatusIndex HASH key"
        # The IAM tab renders these two; `RotationStatus` is NOT what it reads,
        # and rotation.asl.json writes back to `Status`.
        assert item["UserName"]["S"]
        assert "RotationStatus" not in item


def test_rotation_dates_include_overdue_accounts_that_still_alert():
    """An account overdue for rotation and still "active" is exactly the row
    expiry-evaluator-fn must alert on — StatusIndex is queried with
    Status = "active"."""
    from datetime import date

    items = gen.build_accounts(OWNER, 16, _rng())
    overdue = [
        i for i in items
        if date.fromisoformat(i["NextRotationDate"]["S"]) < date.today()
    ]
    assert overdue, "no overdue account: the alerting path has nothing to fire on"
    assert any(i["Status"]["S"] == gen.ACCOUNT_ALERTABLE_STATUS for i in overdue)


def test_account_ids_and_usernames_are_unique():
    items = gen.build_accounts(OWNER, 100, _rng())
    assert len({i["AccountIdHash"]["S"] for i in items}) == len(items)
    assert len({i["UserName"]["S"] for i in items}) == len(items)


# --- Audit events ------------------------------------------------------------


def test_audit_events_hang_off_the_owner_sub_not_a_cert_id():
    """api-audit-fn lets a non-admin query only their own sub, so events keyed on
    a CertId are invisible to a normal login."""
    for item in gen.build_audit_events(OWNER, 30, _rng()):
        assert item["EntityId"]["S"] == OWNER


def test_audit_timestamps_are_distinct_so_events_append_rather_than_overwrite():
    """EventTimestamp is the table's RANGE key — a collision is an overwrite."""
    items = gen.build_audit_events(OWNER, 50, _rng())
    stamps = [i["EventTimestamp"]["S"] for i in items]
    assert len(set(stamps)) == len(stamps)


def test_audit_events_carry_a_ttl():
    for item in gen.build_audit_events(OWNER, 5, _rng()):
        assert int(item["ExpiresAt"]["N"]) > 0


# --- Batching ----------------------------------------------------------------


@pytest.mark.parametrize("counts", [(40, 15, 30), (200, 50, 100), (1, 1, 1), (25, 25, 25)])
def test_no_batch_exceeds_the_25_item_limit(counts):
    """The cap is per request across ALL tables, not per table."""
    certs, accounts, events = counts
    rng = _rng()
    by_table = {
        "certs": gen.to_requests(gen.build_certs(OWNER, certs, rng), ["CertId"], False),
        "iam": gen.to_requests(gen.build_accounts(OWNER, accounts, rng), ["AccountIdHash"], False),
        "audit": gen.to_requests(
            gen.build_audit_events(OWNER, events, rng), ["EntityId", "EventTimestamp"], False
        ),
    }
    batches = list(gen.chunk(by_table))
    for batch in batches:
        assert sum(len(v) for v in batch.values()) <= gen.BATCH_LIMIT

    # Nothing may be dropped in the process.
    total_in = sum(len(v) for v in by_table.values())
    total_out = sum(sum(len(v) for v in b.values()) for b in batches)
    assert total_out == total_in == certs + accounts + events


def test_delete_requests_target_exactly_the_keys_the_put_requests_wrote():
    """--clean must remove precisely what a seed created, key for key."""
    rng = _rng()
    certs = gen.build_certs(OWNER, 10, rng)
    puts = gen.to_requests(certs, ["CertId"], delete=False)
    deletes = gen.to_requests(certs, ["CertId"], delete=True)

    put_keys = [p["PutRequest"]["Item"]["CertId"] for p in puts]
    del_keys = [d["DeleteRequest"]["Key"]["CertId"] for d in deletes]
    assert put_keys == del_keys
    # A DeleteRequest carries the key alone — nothing else.
    for d in deletes:
        assert list(d["DeleteRequest"]["Key"]) == ["CertId"]


def test_generation_is_deterministic_so_reruns_upsert_rather_than_duplicate():
    first = gen.build_certs(OWNER, 20, random.Random(0))
    second = gen.build_certs(OWNER, 20, random.Random(0))
    assert [i["CertId"] for i in first] == [i["CertId"] for i in second]
    assert [i["Status"] for i in first] == [i["Status"] for i in second]


# --- The CLI itself ----------------------------------------------------------


def test_cli_defaults_to_the_shared_owner_when_none_is_given(tmp_path):
    """Forgetting --owner-id must not produce rows nobody can see."""
    subprocess.run(
        [
            sys.executable, str(ROOT / "scripts" / "gen_demo_data.py"),
            "--certs", "2", "--accounts", "0", "--audit-events", "0",
            "--cert-table", "t-certs", "--iam-table", "t-iam", "--audit-table", "t-audit",
            "--out-dir", str(tmp_path),
        ],
        capture_output=True, text=True, check=True,
    )
    for path in tmp_path.glob("batch-*.json"):
        for requests in json.loads(path.read_text()).values():
            for request in requests:
                assert request["PutRequest"]["Item"]["OwnerId"]["S"] == gen.SHARED_OWNER_ID


def test_cli_writes_valid_batch_files(tmp_path):
    result = subprocess.run(
        [
            sys.executable, str(ROOT / "scripts" / "gen_demo_data.py"),
            "--owner-id", OWNER,
            "--certs", "30", "--accounts", "10", "--audit-events", "20",
            "--cert-table", "t-certs", "--iam-table", "t-iam", "--audit-table", "t-audit",
            "--out-dir", str(tmp_path),
        ],
        capture_output=True, text=True, check=True,
    )
    files = [Path(line) for line in result.stdout.split()]
    assert files, "the CLI must print the files it wrote so the wrapper can apply them"

    total = 0
    for path in files:
        payload = json.loads(path.read_text())
        assert set(payload) <= {"t-certs", "t-iam", "t-audit"}
        total += sum(len(v) for v in payload.values())
    assert total == 60


def test_cli_clears_stale_batches_so_a_smaller_rerun_cannot_reapply_old_rows(tmp_path):
    stale = tmp_path / "batch-9999.json"
    stale.write_text('{"t-certs": [{"PutRequest": {"Item": {}}}]}')

    subprocess.run(
        [
            sys.executable, str(ROOT / "scripts" / "gen_demo_data.py"),
            "--owner-id", OWNER,
            "--certs", "1", "--accounts", "1", "--audit-events", "1",
            "--cert-table", "t-certs", "--iam-table", "t-iam", "--audit-table", "t-audit",
            "--out-dir", str(tmp_path),
        ],
        capture_output=True, text=True, check=True,
    )
    assert not stale.exists()
