"""scripts/gen_demo_data.py: demo inventory generation.

The traps this pins down are all silent ones — DynamoDB accepts every mistake
below and simply returns fewer rows than expected:

  - A row missing the GSI's RANGE key (ExpiryDate / NextRotationDate) is written
    successfully and then omitted from the index entirely, so GET /certs never
    returns it.
  - `OwnerId` must be the caller's Cognito sub; OwnerIndex is keyed on it, so any
    other value makes the row invisible to every login.
  - `Status` is the HASH key of ExpiryIndex/StatusIndex and expiry-evaluator-fn
    queries those with the literals "ISSUED" and "active". Any other value is
    invisible to the alerting path.
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

import gen_demo_data as gen  # noqa: E402

OWNER = "d9ca551c-d0a1-7011-1c4f-99a48c8d917f"


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


def test_expiry_dates_cover_every_colour_band():
    """Seeding must exercise the UI's rendering, not just its query. The bands
    are <=7d red, <=30d amber, beyond green."""
    from datetime import date

    items = gen.build_certs(OWNER, 12, _rng())
    days = [(date.fromisoformat(i["ExpiryDate"]["S"]) - date.today()).days for i in items]
    assert any(d <= 7 for d in days), f"no red-band cert: {days}"
    assert any(7 < d <= 30 for d in days), f"no amber-band cert: {days}"
    assert any(d > 30 for d in days), f"no green-band cert: {days}"


def test_expiry_dates_are_in_the_future():
    """A hardcoded date silently ages into the past and renders every row as
    long expired — the bug the previous fixed seed had."""
    from datetime import date

    for item in gen.build_certs(OWNER, 40, _rng()):
        assert date.fromisoformat(item["ExpiryDate"]["S"]) > date.today()


def test_most_certs_are_alertable_but_some_deliberately_are_not():
    items = gen.build_certs(OWNER, 60, _rng())
    statuses = [i["Status"]["S"] for i in items]
    alertable = statuses.count(gen.CERT_ALERTABLE_STATUS)
    assert alertable > len(statuses) / 2, "most rows must be queryable by ExpiryIndex"
    assert alertable < len(statuses), "some rows must be excluded, to prove the filter works"


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
