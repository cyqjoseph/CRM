"""Shared helpers for Centralised Resource Manager Lambda functions."""
import functools
import hashlib
import json
import os
import sys
import time
import traceback
import uuid
from datetime import datetime, timezone
from decimal import Decimal

import boto3

AUDIT_TABLE_NAME = os.environ.get("AUDIT_TABLE_NAME", "")
AUDIT_TTL_DAYS = int(os.environ.get("AUDIT_TTL_DAYS", "90"))
# The API's Cors property only generates the OPTIONS preflight method. A Lambda
# proxy integration's own responses carry exactly the headers the function sets,
# so every real response needs this header too or the browser blocks the read.
# Kept in step with CrmApi's Cors property in template.yaml.
CORS_ALLOW_ORIGIN = os.environ.get("CORS_ALLOW_ORIGIN", "*")
CORS_ALLOW_METHODS = os.environ.get("CORS_ALLOW_METHODS", "GET, POST, OPTIONS")
CORS_ALLOW_HEADERS = os.environ.get("CORS_ALLOW_HEADERS", "Content-Type, Authorization")

# The one partition every CRM login can read. OwnerIndex is keyed on OwnerId, so
# the value of OwnerId is what decides who can see a row — and while discovery
# and the seeder wrote a *different* OwnerId per Cognito sub, each login saw only
# the rows seeded for it and the team saw three different dashboards. The project
# team shares its assets, so the inventory rows live in one shared partition and
# every authenticated caller reads it.
#
# Kept in step with Globals.Function.Environment.Variables.SHARED_OWNER_ID and
# Ec2DiscoveryFunction's OWNER_ID in template.yaml.
SHARED_OWNER_ID = os.environ.get("SHARED_OWNER_ID", "crm-resource-owners")

# `Status` is the HASH key of CertInventoryTable's ExpiryIndex, and
# expiry-evaluator-fn queries it with the literal "ISSUED". Any other value makes
# a row invisible to expiry alerting — which is how ec2-discovery-fn's
# "active"/"expiring-soon" rows ended up excluded from every alert while looking
# fine in the table. One vocabulary, defined here, used by every writer.
CERT_STATUS_ISSUED = "ISSUED"
CERT_STATUS_EXPIRED = "EXPIRED"
# Statuses a cert can carry that are not derived from its expiry date at all.
CERT_STATUS_REVOKED = "REVOKED"
CERT_STATUS_PENDING_VALIDATION = "PENDING_VALIDATION"


def dynamodb_resource():
    return boto3.resource("dynamodb")


def put_audit_event(entity_id, event_type, actor, outcome, detail=None, table_name=None):
    """Append-only write to the audit hot table. Never raises to the caller's main path.

    EventTimestamp is stored as an ISO-8601 string (not epoch) so that Lambda
    writes and the Step Functions native `dynamodb:putItem` integration (which
    supplies `$$.State.EnteredTime` as ISO-8601) sort and query identically.
    """
    table_name = table_name or AUDIT_TABLE_NAME
    if not table_name:
        return
    table = dynamodb_resource().Table(table_name)
    now = int(time.time())
    table.put_item(
        Item={
            "EntityId": entity_id,
            "EventTimestamp": datetime.now(timezone.utc).isoformat(),
            "EventType": event_type,
            "Actor": actor,
            "Outcome": outcome,
            "Detail": detail or {},
            "ExpiresAt": now + AUDIT_TTL_DAYS * 86400,
        }
    )


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def hash_identifier(value):
    """One-way hash for account identifiers; never store plaintext identifiers."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Decimal):
            return int(o) if o % 1 == 0 else float(o)
        return super().default(o)


def api_response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": CORS_ALLOW_ORIGIN,
            "Access-Control-Allow-Methods": CORS_ALLOW_METHODS,
            "Access-Control-Allow-Headers": CORS_ALLOW_HEADERS,
        },
        "body": json.dumps(body, cls=DecimalEncoder),
    }


def guard_api_handler(handler):
    """Turn an unhandled exception in a browser-facing handler into a 500.

    API Gateway answers a raising proxy-integration Lambda with a bare 502 that
    carries none of the headers the function would have set — so the browser
    reports a CORS failure, the UI shows "Failed to fetch", and the real reason
    exists only in CloudWatch. A well-formed 500 keeps the CORS header and gives
    the UI something to display, while the traceback still reaches the log.

    Only for API Gateway-fronted handlers. The event-driven functions must keep
    raising, or Step Functions retries and SQS redrive-to-DLQ stop working.
    """

    @functools.wraps(handler)
    def wrapper(event, context):
        try:
            return handler(event, context)
        except Exception:
            print(
                "unhandled error in %s %s: %s"
                % (
                    (event or {}).get("httpMethod", "?"),
                    (event or {}).get("resource", "?"),
                    traceback.format_exc(),
                ),
                file=sys.stderr,
            )
            # Deliberately generic: the traceback belongs in CloudWatch, not in
            # a response the browser can read.
            return api_response(500, {"message": "internal error"})

    return wrapper


def _redact_headers(headers):
    if not headers:
        return {}
    return {
        key: ("***redacted***" if key.lower() == "authorization" else value)
        for key, value in headers.items()
    }


def request_headers(event):
    """This event's headers, with Authorization redacted.

    Authorization carries the caller's live Cognito ID token — logging it
    verbatim would let anyone with CloudWatch read access replay the request
    as that user, so every diagnostic log goes through this instead of the
    raw `event["headers"]`.
    """
    return _redact_headers((event or {}).get("headers"))


def request_origin(event):
    headers = (event or {}).get("headers") or {}
    return headers.get("Origin") or headers.get("origin")


def sanitize_event_for_logging(event):
    """A copy of the API Gateway event safe to pass to `structured_log`."""
    event = dict(event or {})
    if event.get("headers"):
        event["headers"] = _redact_headers(event["headers"])
    if event.get("multiValueHeaders"):
        event["multiValueHeaders"] = {
            key: value if key.lower() != "authorization" else ["***redacted***"]
            for key, value in event["multiValueHeaders"].items()
        }
    return event


def get_claims(event):
    return (event.get("requestContext") or {}).get("authorizer", {}).get("claims", {}) or {}


def is_admin(claims):
    groups = claims.get("cognito:groups", "")
    if isinstance(groups, list):
        return "admins" in groups
    return "admins" in groups.split(",")


def owner_id_of(claims):
    return claims.get("sub", "")


def visible_owner_ids(claims):
    """Every OwnerId partition this caller may read, shared partition first.

    The caller's own sub stays in the list so rows seeded per-login before the
    move to a shared partition remain readable rather than vanishing from the
    dashboard the moment this ships.
    """
    owner_ids = [SHARED_OWNER_ID]
    own = owner_id_of(claims)
    if own and own != SHARED_OWNER_ID:
        owner_ids.append(own)
    return owner_ids


def can_view(item, claims):
    """Whether this caller may read/act on one inventory row.

    Admins see everything; everyone else sees the shared team inventory plus
    anything still owned by their own sub.
    """
    if is_admin(claims):
        return True
    return (item or {}).get("OwnerId") in visible_owner_ids(claims)


def query_owner_partitions(table, index_name, key_name, claims, owner_id_override=None):
    """Query `index_name` once per visible owner partition and merge the results.

    DynamoDB has no OR across partition keys, so a union of partitions is a
    query per partition. Results are de-duplicated on `key_name`: the same
    CertId can legitimately be returned twice while rows are mid-migration from
    a per-login partition to the shared one, and the UI must not show it twice.
    """
    owner_ids = [owner_id_override] if owner_id_override else visible_owner_ids(claims)

    merged = {}
    for owner_id in owner_ids:
        paginate_from = None
        while True:
            kwargs = {
                "IndexName": index_name,
                "KeyConditionExpression": "OwnerId = :owner",
                "ExpressionAttributeValues": {":owner": owner_id},
            }
            if paginate_from:
                kwargs["ExclusiveStartKey"] = paginate_from
            response = table.query(**kwargs)
            for item in response.get("Items", []):
                merged.setdefault(item[key_name], item)
            paginate_from = response.get("LastEvaluatedKey")
            if not paginate_from:
                break
    return list(merged.values())


def cert_status_for(expiry, now=None):
    """The Status literal a certificate with this expiry should carry.

    Only ever ISSUED or EXPIRED: a cert's lifecycle status has to agree with its
    own expiry date, or the dashboard shows rows reading "ISSUED" that expired
    weeks ago. REVOKED/PENDING_VALIDATION are set explicitly by whoever knows
    that out-of-band fact, never inferred from a date.
    """
    now = now or datetime.now(timezone.utc)
    if isinstance(expiry, str):
        expiry = datetime.fromisoformat(expiry)
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return CERT_STATUS_EXPIRED if expiry < now else CERT_STATUS_ISSUED


def new_request_id():
    return str(uuid.uuid4())


def structured_log(request_id, event_type, level="INFO", **fields):
    """Emit one JSON line to stdout — CloudWatch Logs captures it as a single,
    greppable/filterable structured event rather than an opaque format string.
    """
    print(json.dumps({"requestId": request_id, "level": level, "eventType": event_type, **fields}, default=str))
