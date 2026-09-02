#!/usr/bin/env python3
"""Generate DynamoDB batch-write-item payloads for demo inventory data.

Emits JSON files for `aws dynamodb batch-write-item --request-items file://...`
rather than writing to DynamoDB itself. Two reasons:

  1. Standard library only. This runs from deploy.sh on the platform's build
     host, where `python3` and the AWS CLI are both guaranteed but an importable
     `boto3` is not.
  2. The write then happens under whatever role invoked the CLI. That matters:
     the tables are writable by the deploy role and by the stack's own Lambda
     execution roles, but a human IAM user in this account is not granted
     dynamodb:PutItem, so seeding from a laptop can fail with AccessDenied while
     the identical call from deploy.sh succeeds.

Every generated id starts with DEMO_PREFIX, so --delete removes exactly the rows
this script created and can never touch a genuinely discovered resource.

Usage (see scripts/seed-demo-data.sh for the wrapper that applies these):

    python3 scripts/gen_demo_data.py --certs 40 --accounts 15 \
        --audit-events 30 --out-dir /tmp/seed

Rows are owned by the shared team partition (crm-resource-owners) by default, so
every CRM login sees the same inventory. Pass --owner-id to target one Cognito
sub instead.
"""
import argparse
import hashlib
import json
import random
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

# BatchWriteItem hard limit: 25 items per request.
BATCH_LIMIT = 25

DEMO_PREFIX = "demo-"

# The partition every CRM login reads. Kept in step with
# crm_common.SHARED_OWNER_ID and template.yaml's SHARED_OWNER_ID env var.
SHARED_OWNER_ID = "crm-resource-owners"

# Rows a previous deploy.sh wrote with hand-written put-item calls before this
# generator existed (that script is gone — commit 6e12d0d — but its rows are
# not). They are owned by one Cognito sub, carry hardcoded 2025 dates, and use a
# status vocabulary ("active"/"warning"/"critical") that no query in this
# application looks for. Nothing updates them and nothing else will ever remove
# them.
#
# Named individually rather than matched by prefix precisely because they lack
# the `demo-` prefix that makes every other id here safe to delete by pattern:
# an id-by-id list cannot widen into something that reaches a discovered row.
LEGACY_FIXED_CERT_IDS = ("cert-001", "cert-002", "cert-003")
LEGACY_FIXED_ACCOUNT_IDS = ("hash-acct-001", "hash-acct-002")

# `Status` is not cosmetic — it is the HASH key of ExpiryIndex/StatusIndex, and
# expiry-evaluator-fn queries those with these exact literals. A row with any
# other Status is invisible to the alerting path. Kept in step with
# crm_common.CERT_STATUS_* (asserted by tests/test_gen_demo_data.py); duplicated
# rather than imported because this script is deliberately stdlib-only — see the
# module docstring.
CERT_ALERTABLE_STATUS = "ISSUED"
CERT_EXPIRED_STATUS = "EXPIRED"
# Statuses that are facts about a certificate's lifecycle rather than a function
# of its expiry date, so they can sit on a row whose date is still in the future.
CERT_REVOKED_STATUS = "REVOKED"
CERT_PENDING_STATUS = "PENDING_VALIDATION"
CERT_OTHER_STATUSES = (CERT_EXPIRED_STATUS, CERT_PENDING_STATUS, CERT_REVOKED_STATUS)
ACCOUNT_ALERTABLE_STATUS = "active"
ACCOUNT_OTHER_STATUSES = ("warning", "critical")

CERT_TYPES = ("ACM", "Self-Signed", "On-Prem", "IAM_SERVER_CERT")

SERVICES = (
    "payments", "sso", "api", "checkout", "identity", "billing", "reporting",
    "inventory", "notifications", "search", "gateway", "admin", "vpn", "mail",
    "backup", "metrics", "audit", "scheduler", "webhooks", "cdn",
)
ZONES = ("internal.example.com", "example.com", "corp.example.net", "svc.example.io")

AUDIT_EVENTS = (
    ("DISCOVERY_COMPLETED", "SUCCESS"),
    ("EXPIRY_ALERT", "ALERTED"),
    ("EXPIRY_ALERT", "PARTIAL"),
    ("MANUAL_RENEWAL_TRIGGER", "STARTED"),
    ("RENEWAL_COMPLETE", "SUCCESS"),
    ("RENEWAL_COMPLETE", "FAILURE"),
    ("MANUAL_ROTATION_TRIGGER", "STARTED"),
    ("ROTATION_COMPLETE", "SUCCESS"),
    ("PASSWORD_RESET_REQUESTED", "STARTED"),
    ("NOTIFICATION_SENT", "SUCCESS"),
)

# The bands the UI distinguishes, as (name, min_days, max_days) relative to today.
# Generation guarantees coverage of each rather than leaving it to chance, so
# seeding exercises the rendering and not just the query.
#
# "expired" is deliberately in the past. Every seeded row used to be future-dated,
# which meant a certificate inventory whose entire reason to exist is expiry
# tracking could not show a single expired certificate — and rows reading "ISSUED,
# expires tomorrow" looked like the data made no sense, because a status picked
# independently of the date is not a status.
BANDS = (
    ("expired", -180, -1),
    ("red", 1, 7),       # <= 7 days
    ("amber", 8, 30),    # <= 30 days
    ("green", 31, 400),
)

# Index of the green band in BANDS — the only band a PENDING_VALIDATION row may
# land in, since a certificate still awaiting validation has not been issued yet
# and cannot be days from expiry.
_GREEN_BAND = 3


def _band_for(index):
    return BANDS[index % len(BANDS)]


def _cert_status(rng, index, days):
    """The Status a row with this expiry should carry.

    Derived from the date, never independent of it: a past date is EXPIRED, full
    stop. A deliberate minority of future-dated rows carries REVOKED (revocation
    says nothing about remaining validity) or, in the green band only,
    PENDING_VALIDATION — so the ExpiryIndex filter has something to exclude and
    the UI has more than one status to render.
    """
    if days < 0:
        return CERT_EXPIRED_STATUS
    if index % 9 == 4:
        return CERT_REVOKED_STATUS
    if index % 9 == 7 and _band_for(index)[0] == "green":
        return CERT_PENDING_STATUS
    return CERT_ALERTABLE_STATUS


def _days_out(rng, index, total):
    """Spread expiry across every band, guaranteeing each is represented."""
    _, low, high = _band_for(index)
    return rng.randint(low, high)


def _iso_date(days_from_now):
    return (date.today() + timedelta(days=days_from_now)).isoformat()


def _hash_id(value):
    """Mirrors crm_common.hash_identifier so demo rows look like discovered ones."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def build_certs(owner_id, count, rng):
    items = []
    for i in range(count):
        service = SERVICES[i % len(SERVICES)]
        zone = ZONES[i % len(ZONES)]
        # Distinct hostname per row even once SERVICES wraps around.
        domain = f"{service}-{i // len(SERVICES)}.{zone}" if i >= len(SERVICES) else f"{service}.{zone}"
        days = _days_out(rng, i, count)
        status = _cert_status(rng, i, days)

        items.append(
            {
                "CertId": {"S": f"{DEMO_PREFIX}cert-{i:04d}"},
                "CertType": {"S": CERT_TYPES[i % len(CERT_TYPES)]},
                # OwnerIndex HASH. The shared team partition by default, so every
                # CRM login sees the same inventory — a per-Cognito-sub value here
                # gave each member their own private dashboard.
                "OwnerId": {"S": owner_id},
                "Domain": {"S": domain},
                # OwnerIndex RANGE *and* ExpiryIndex RANGE. DynamoDB accepts a
                # row without it and silently omits it from both indexes.
                "ExpiryDate": {"S": _iso_date(days)},
                # Always consistent with ExpiryDate above — see _cert_status.
                "Status": {"S": status},
                "Source": {"S": "demo-seed"},
                "EnvironmentTag": {"S": "aws" if i % 3 else "on-prem"},
                "LastSyncedAt": {"S": datetime.now(timezone.utc).isoformat()},
                "Version": {"N": "1"},
            }
        )
    return items


# Rotation bands, as (name, min_days, max_days) for NextRotationDate. Unlike a
# certificate's expiry, `Status` here is a rotation-health flag rather than a
# function of the date: an account whose rotation is overdue and still "active" is
# exactly the row expiry-evaluator-fn must alert on (StatusIndex is queried with
# Status = "active"), so the overdue band deliberately keeps that status.
ROTATION_BANDS = (
    ("overdue", -90, -1),
    ("due-soon", 1, 7),
    ("due", 8, 30),
    ("scheduled", 31, 400),
)


def build_accounts(owner_id, count, rng):
    items = []
    for i in range(count):
        service = SERVICES[i % len(SERVICES)]
        user_name = f"svc-{service}" if i < len(SERVICES) else f"svc-{service}-{i // len(SERVICES)}"
        _, low, high = ROTATION_BANDS[i % len(ROTATION_BANDS)]
        days = rng.randint(low, high)
        key_age = rng.randint(1, 400)

        status = (
            rng.choice(ACCOUNT_OTHER_STATUSES)
            if i % 4 == 3
            else ACCOUNT_ALERTABLE_STATUS
        )

        items.append(
            {
                # Keep the demo prefix readable rather than hashing it away —
                # --delete needs to recognise these, and the UI shows the value.
                "AccountIdHash": {"S": f"{DEMO_PREFIX}acct-{_hash_id(user_name)[:16]}"},
                # The IAM tab's "User" column. Not RotationStatus — the UI and
                # rotation.asl.json both read `Status`.
                "UserName": {"S": user_name},
                "OwnerId": {"S": owner_id},
                "NextRotationDate": {"S": _iso_date(days)},
                "Status": {"S": status},
                "LastRotated": {"S": _iso_date(-key_age)},
                "KeyAge": {"N": str(key_age)},
                "Source": {"S": "demo-seed"},
                "EnvironmentTag": {"S": "aws"},
                "LastSyncedAt": {"S": datetime.now(timezone.utc).isoformat()},
                "Version": {"N": "1"},
            }
        )
    return items


def build_audit_events(owner_id, count, rng, ttl_days=90):
    """Events keyed on the owner id, so the seeded trail sits in one partition.

    There is no audit search endpoint any more (it answered 403 to every search
    anyone actually typed), so these rows exist to give audit-exporter-fn and the
    TTL something real to work on, and to make the table legible to whoever opens
    it in the console.
    """
    expires_at = int(datetime.now(timezone.utc).timestamp()) + ttl_days * 86400
    items = []
    for i in range(count):
        event_type, outcome = AUDIT_EVENTS[i % len(AUDIT_EVENTS)]
        # Distinct timestamps: EventTimestamp is the table's RANGE key, so a
        # collision would overwrite the previous event rather than append.
        ts = datetime.now(timezone.utc) - timedelta(minutes=7 * (i + 1))
        items.append(
            {
                "EntityId": {"S": owner_id},
                "EventTimestamp": {"S": ts.isoformat()},
                "EventType": {"S": event_type},
                "Actor": {"S": "demo-seed"},
                "Outcome": {"S": outcome},
                "Detail": {
                    "M": {
                        "note": {"S": f"demo event {i + 1} of {count}"},
                        "severity": {"S": rng.choice(("low", "medium", "high"))},
                    }
                },
                "ExpiresAt": {"N": str(expires_at)},
            }
        )
    return items


def build_legacy_fixed_keys():
    """Key-only items for the legacy fixed rows, ready for to_requests(delete=True).

    Keys alone: a DeleteRequest carries nothing else, and these rows must never be
    re-created — only removed.
    """
    certs = [{"CertId": {"S": cert_id}} for cert_id in LEGACY_FIXED_CERT_IDS]
    accounts = [{"AccountIdHash": {"S": account_id}} for account_id in LEGACY_FIXED_ACCOUNT_IDS]
    return certs, accounts


def _key_only(item, key_names):
    return {name: item[name] for name in key_names}


def to_requests(items, key_names, delete):
    if delete:
        return [{"DeleteRequest": {"Key": _key_only(i, key_names)}} for i in items]
    return [{"PutRequest": {"Item": i}} for i in items]


def chunk(requests_by_table, limit=BATCH_LIMIT):
    """Split into BatchWriteItem-sized payloads.

    The limit is 25 requests per call TOTAL, across every table in the payload —
    not per table — so this flattens first and then slices.
    """
    flat = [
        (table, request)
        for table, requests in requests_by_table.items()
        for request in requests
    ]
    for start in range(0, len(flat), limit):
        payload = {}
        for table, request in flat[start : start + limit]:
            payload.setdefault(table, []).append(request)
        yield payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner-id", default=SHARED_OWNER_ID,
                        help="OwnerIndex HASH key for these rows (default: the shared "
                             "team partition every CRM login can read)")
    parser.add_argument("--certs", type=int, default=40)
    parser.add_argument("--accounts", type=int, default=15)
    parser.add_argument("--audit-events", type=int, default=30)
    parser.add_argument("--cert-table", required=True)
    parser.add_argument("--iam-table", required=True)
    parser.add_argument("--audit-table", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--delete", action="store_true",
                        help="emit DeleteRequests for the same ids instead of PutRequests")
    parser.add_argument("--retire-legacy-fixed", action="store_true",
                        help="emit DeleteRequests for the fixed rows an earlier deploy.sh "
                             "left behind (cert-001..003, hash-acct-001..002) and nothing else")
    parser.add_argument("--seed", type=int, default=0,
                        help="RNG seed; fixed by default so re-runs upsert the same rows")
    args = parser.parse_args()

    if args.retire_legacy_fixed:
        # Deletes only, and only the named ids — no generated rows at all.
        legacy_certs, legacy_accounts = build_legacy_fixed_keys()
        requests_by_table = {
            args.cert_table: to_requests(legacy_certs, ["CertId"], delete=True),
            args.iam_table: to_requests(legacy_accounts, ["AccountIdHash"], delete=True),
        }
    else:
        rng = random.Random(args.seed)
        certs = build_certs(args.owner_id, args.certs, rng)
        accounts = build_accounts(args.owner_id, args.accounts, rng)
        audit = build_audit_events(args.owner_id, args.audit_events, rng)

        requests_by_table = {
            args.cert_table: to_requests(certs, ["CertId"], args.delete),
            args.iam_table: to_requests(accounts, ["AccountIdHash"], args.delete),
            args.audit_table: to_requests(audit, ["EntityId", "EventTimestamp"], args.delete),
        }
    requests_by_table = {k: v for k, v in requests_by_table.items() if v}

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for stale in out_dir.glob("batch-*.json"):
        stale.unlink()

    written = []
    for index, payload in enumerate(chunk(requests_by_table)):
        path = out_dir / f"batch-{index:04d}.json"
        path.write_text(json.dumps(payload, indent=2))
        written.append(path)

    for path in written:
        print(path)


if __name__ == "__main__":
    main()
