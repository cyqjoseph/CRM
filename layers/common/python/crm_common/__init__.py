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


def new_request_id():
    return str(uuid.uuid4())


def structured_log(request_id, event_type, level="INFO", **fields):
    """Emit one JSON line to stdout — CloudWatch Logs captures it as a single,
    greppable/filterable structured event rather than an opaque format string.
    """
    print(json.dumps({"requestId": request_id, "level": level, "eventType": event_type, **fields}, default=str))
