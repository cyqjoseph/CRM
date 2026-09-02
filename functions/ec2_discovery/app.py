"""ec2-discovery-fn: discovers OS-level certificates from the cert-scanner EC2
instance (see Ec2CertScannerInstance in template.yaml) and merges them into the
cert inventory table.

Triggered every 30 minutes by Ec2DiscoveryScheduleRule. One SSM Run Command
does both the enumeration and the parsing: it lists every *.pem under
/etc/ssl/certs and, for each, runs `openssl x509 -text` wrapped in file
markers, so a single SendCommand/GetCommandInvocation round trip yields every
certificate's full text in one stdout blob — avoiding one SSM round trip per
certificate, which would not fit this function's Lambda timeout.

Discovered rows are merged (never replaced): an existing CertId's ExpiryDate/
Status/LastDiscoveredAt are updated in place, a new CertId is inserted, and
nothing already in the table is ever deleted here.
"""
import hashlib
import os
import re
import time
from datetime import datetime, timedelta, timezone

import boto3
import botocore.exceptions

from crm_common import structured_log

INSTANCE_ID_PARAM_NAME = os.environ["EC2_INSTANCE_ID_PARAM"]
CERT_TABLE_NAME = os.environ["CERT_TABLE"]
OWNER_ID = os.environ["OWNER_ID"]

SOURCE_NAME = "ec2-os-certs"
EXPIRING_SOON_WINDOW_DAYS = 30
COMMAND_POLL_INTERVAL_SECONDS = 2
COMMAND_POLL_BUDGET_SECONDS = 20
DYNAMODB_MAX_RETRIES = 3
DYNAMODB_RETRY_BASE_DELAY_SECONDS = 0.5

# Best-effort enumeration of the OS certificate store, each cert's full text
# wrapped in markers so multiple certs' openssl output can be told apart in one
# stdout blob. Ubuntu populates /etc/ssl/certs with per-certificate .pem
# symlinks, so this needs no knowledge of which CAs are installed.
CERT_SCAN_COMMAND = (
    'for f in $(find /etc/ssl/certs -name "*.pem" -type f | head -100); do '
    'echo "===CERT_FILE_START:$f==="; '
    'openssl x509 -in "$f" -text -noout -nameopt RFC2253 2>/dev/null '
    '|| echo "===CERT_PARSE_ERROR:$f==="; '
    'echo "===CERT_FILE_END:$f==="; '
    "done"
)

_FILE_START_RE = re.compile(r"===CERT_FILE_START:(.*?)===\n")
_SERIAL_BLOCK_RE = re.compile(r"Serial Number:\s*\n\s*([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{2})+)")
_SERIAL_INLINE_RE = re.compile(r"Serial Number:\s*\d+\s*\(0x([0-9a-fA-F]+)\)")
_SERIAL_FALLBACK_RE = re.compile(r"Serial Number:\s*([0-9a-fA-Fx]+)")
_ISSUER_RE = re.compile(r"^\s*Issuer:\s*(.+)$", re.MULTILINE)
_SUBJECT_RE = re.compile(r"^\s*Subject:\s*(.+)$", re.MULTILINE)
_NOT_BEFORE_RE = re.compile(r"Not Before\s*:\s*(.+)")
_NOT_AFTER_RE = re.compile(r"Not After\s*:\s*(.+)")
_SAN_RE = re.compile(r"X509v3 Subject Alternative Name:\s*\n\s*(.+)")

# Substrings (lower-cased) of well-known public root/intermediate CA issuer
# DNs. /etc/ssl/certs is the OS trust store, so almost everything here is a
# system CA; anything issued by an unrecognised issuer is assumed to be an
# application-installed certificate instead.
_KNOWN_ROOT_CA_MARKERS = (
    "digicert", "let's encrypt", "isrg", "globalsign", "verisign", "godaddy",
    "sectigo", "comodo", "entrust", "usertrust", "amazon", "identrust",
    "geotrust", "thawte", "starfield", "baltimore", "quovadis", "certum",
    "actalis", "buypass", "ssl.com", "trustcor", "microsoft", "apple",
    "google trust", " gts ",
)


def _split_cert_blocks(stdout):
    """Split CERT_SCAN_COMMAND's stdout into (path, block_text) pairs.

    block_text is None when the openssl call for that file failed (the
    ===CERT_PARSE_ERROR marker fired instead of producing text).
    """
    parts = _FILE_START_RE.split(stdout)
    blocks = []
    pairs = iter(parts[1:])
    for path, rest in zip(pairs, pairs):
        end_marker = f"===CERT_FILE_END:{path}==="
        end_idx = rest.find(end_marker)
        body = rest[:end_idx] if end_idx != -1 else rest
        if f"===CERT_PARSE_ERROR:{path}===" in body:
            blocks.append((path, None))
        else:
            blocks.append((path, body))
    return blocks


def _search(pattern, text):
    match = pattern.search(text)
    return match.group(1).strip() if match else None


def _parse_serial(text):
    match = _SERIAL_BLOCK_RE.search(text)
    if match:
        return match.group(1).replace(":", "").lower()
    match = _SERIAL_INLINE_RE.search(text)
    if match:
        return match.group(1).lower()
    match = _SERIAL_FALLBACK_RE.search(text)
    if match:
        return match.group(1).lower()
    return None


def _parse_openssl_date(raw):
    return datetime.strptime(raw.strip(), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def _parse_sans(text):
    match = _SAN_RE.search(text)
    if not match:
        return []
    entries = [entry.strip() for entry in match.group(1).split(",")]
    return [entry.split(":", 1)[1] for entry in entries if entry.startswith("DNS:")]


def _extract_cn(dn):
    if not dn:
        return None
    for part in dn.split(","):
        part = part.strip()
        if part.upper().startswith("CN="):
            return part[3:]
    return None


def _compute_cert_id(serial, instance_id):
    digest = hashlib.sha256(f"{serial}{instance_id}".encode("utf-8")).hexdigest()
    return f"ec2-{digest}"


def _compute_status(expiry_dt, now):
    if expiry_dt < now:
        return "expired"
    if expiry_dt < now + timedelta(days=EXPIRING_SOON_WINDOW_DAYS):
        return "expiring-soon"
    return "active"


def _classify_cert_type(issuer_dn):
    if not issuer_dn:
        return "app-cert"
    lowered = issuer_dn.lower()
    return "system-ca" if any(marker in lowered for marker in _KNOWN_ROOT_CA_MARKERS) else "app-cert"


def _build_cert_item(block, instance_id, now):
    """Turn one openssl x509 -text block into a cert-inventory item, or None
    if it lacks the minimum fields (serial, expiry) needed to be useful."""
    serial = _parse_serial(block)
    not_after_raw = _search(_NOT_AFTER_RE, block)
    if not serial or not not_after_raw:
        return None

    not_before_raw = _search(_NOT_BEFORE_RE, block)
    issuer_dn = _search(_ISSUER_RE, block)
    subject_dn = _search(_SUBJECT_RE, block)
    sans = _parse_sans(block)

    expiry_dt = _parse_openssl_date(not_after_raw)
    issue_dt = _parse_openssl_date(not_before_raw) if not_before_raw else None

    subject_cn = _extract_cn(subject_dn)
    issuer_cn = _extract_cn(issuer_dn)
    domain = subject_cn or (sans[0] if sans else None) or issuer_cn or "unknown"

    item = {
        "CertId": _compute_cert_id(serial, instance_id),
        "OwnerId": OWNER_ID,
        "Domain": domain,
        "Issuer": issuer_dn or issuer_cn or "unknown",
        "IssueDate": issue_dt.isoformat() if issue_dt else None,
        "ExpiryDate": expiry_dt.isoformat(),
        "Status": _compute_status(expiry_dt, now),
        "Source": SOURCE_NAME,
        "CertType": _classify_cert_type(issuer_dn),
        "LastDiscoveredAt": now.isoformat(),
    }
    return {k: v for k, v in item.items() if v is not None}


def _get_instance_id(ssm, request_id):
    try:
        return ssm.get_parameter(Name=INSTANCE_ID_PARAM_NAME)["Parameter"]["Value"]
    except botocore.exceptions.ClientError as exc:
        structured_log(request_id, "EC2_DISCOVERY_NO_INSTANCE", level="ERROR", error=str(exc))
        return None


def _wait_for_command(ssm, instance_id, command_id, request_id, budget_seconds):
    deadline = time.monotonic() + budget_seconds
    last_status = None
    while time.monotonic() < deadline:
        try:
            invocation = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except botocore.exceptions.ClientError as exc:
            # The invocation record does not exist for a brief window right
            # after dispatch — keep polling rather than treating it as fatal.
            if exc.response.get("Error", {}).get("Code") != "InvocationDoesNotExist":
                raise
            time.sleep(COMMAND_POLL_INTERVAL_SECONDS)
            continue
        last_status = invocation.get("Status")
        if last_status in ("Success", "Failed", "Cancelled", "TimedOut"):
            return invocation
        time.sleep(COMMAND_POLL_INTERVAL_SECONDS)
    structured_log(
        request_id, "EC2_DISCOVERY_COMMAND_POLL_TIMED_OUT",
        level="ERROR", commandId=command_id, lastStatus=last_status,
    )
    return None


def _dispatch_and_collect(ssm, instance_id, request_id):
    """Send the cert-scan command, retrying the dispatch once if the first
    attempt's command never completes within budget. Returns the command's
    stdout, or None if neither attempt completes in time."""
    for attempt in (1, 2):
        try:
            response = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Comment="app-d9fae51c-1929cc69 OS certificate discovery",
                Parameters={"commands": [CERT_SCAN_COMMAND]},
            )
        except botocore.exceptions.ClientError as exc:
            structured_log(
                request_id, "EC2_DISCOVERY_DISPATCH_FAILED", level="ERROR",
                instanceId=instance_id, attempt=attempt, error=str(exc),
            )
            if attempt == 2:
                raise
            continue

        command_id = response["Command"]["CommandId"]
        invocation = _wait_for_command(ssm, instance_id, command_id, request_id, COMMAND_POLL_BUDGET_SECONDS)
        if invocation is not None:
            return invocation.get("StandardOutputContent", "")
        structured_log(request_id, "EC2_DISCOVERY_COMMAND_TIMEOUT_RETRY", commandId=command_id, attempt=attempt)
    return None


def _existing_certs_by_id(table, owner_id):
    """Every cert already discovered from this source, keyed by CertId.

    OwnerId is constant ("crm-resource-owners") for every row this function
    writes, so OwnerIndex turns this into a cheap Query rather than the
    full-table Scan a Source-keyed lookup would otherwise need — no GSI on
    Source exists in template.yaml.
    """
    existing = {}
    query_kwargs = {
        "IndexName": "OwnerIndex",
        "KeyConditionExpression": "OwnerId = :owner",
        "ExpressionAttributeValues": {":owner": owner_id},
    }
    while True:
        response = table.query(**query_kwargs)
        for item in response.get("Items", []):
            if item.get("Source") == SOURCE_NAME:
                existing[item["CertId"]] = item
        last_key = response.get("LastEvaluatedKey")
        if not last_key:
            return existing
        query_kwargs["ExclusiveStartKey"] = last_key


def _with_retry(request_id, event_type, cert_id, fn):
    delay = DYNAMODB_RETRY_BASE_DELAY_SECONDS
    for attempt in range(1, DYNAMODB_MAX_RETRIES + 1):
        try:
            fn()
            return
        except Exception as exc:
            structured_log(
                request_id, event_type, level="ERROR",
                certId=cert_id, attempt=attempt, error=str(exc),
            )
            if attempt == DYNAMODB_MAX_RETRIES:
                raise
            time.sleep(delay)
            delay *= 2


def _publish_error_metric(request_id):
    try:
        boto3.client("cloudwatch").put_metric_data(
            Namespace="app-d9fae51c-1929cc69/Ec2Discovery",
            MetricData=[{"MetricName": "DiscoveryFatalErrors", "Value": 1, "Unit": "Count"}],
        )
    except Exception as exc:
        structured_log(request_id, "EC2_DISCOVERY_METRIC_PUBLISH_FAILED", level="WARNING", error=str(exc))


def handler(event, context):
    request_id = getattr(context, "aws_request_id", "local")
    start = time.monotonic()
    structured_log(request_id, "EC2_DISCOVERY_CYCLE_START", timestamp=datetime.now(timezone.utc).isoformat())

    ssm = boto3.client("ssm")

    instance_id = _get_instance_id(ssm, request_id)
    if instance_id is None:
        return {"discovered": 0, "reason": "instance-id parameter not found"}

    stdout = _dispatch_and_collect(ssm, instance_id, request_id)
    if stdout is None:
        structured_log(request_id, "EC2_DISCOVERY_NO_OUTPUT", level="ERROR", instanceId=instance_id)
        return {"instanceId": instance_id, "totalCertsFound": 0, "reason": "command did not complete"}

    now = datetime.now(timezone.utc)
    items = []
    for path, block in _split_cert_blocks(stdout):
        item = None
        if block is not None:
            try:
                item = _build_cert_item(block, instance_id, now)
            except Exception as exc:
                structured_log(request_id, "EC2_DISCOVERY_CERT_PARSE_FAILED", level="WARNING", path=path, error=str(exc))
        if item is None:
            if block is not None:
                structured_log(request_id, "EC2_DISCOVERY_CERT_PARSE_FAILED", level="WARNING", path=path)
            continue
        items.append(item)

    table = boto3.resource("dynamodb").Table(CERT_TABLE_NAME)
    try:
        existing = _existing_certs_by_id(table, OWNER_ID)
    except Exception as exc:
        structured_log(request_id, "EC2_DISCOVERY_QUERY_FAILED", level="ERROR", error=str(exc))
        existing = {}

    new_count = updated_count = unchanged_count = 0
    try:
        for item in items:
            cert_id = item["CertId"]
            prior = existing.get(cert_id)

            if prior is None:
                _with_retry(request_id, "EC2_DISCOVERY_WRITE_FAILED", cert_id, lambda item=item: table.put_item(Item=item))
                new_count += 1
                action = "new"
            else:
                changed = prior.get("ExpiryDate") != item["ExpiryDate"] or prior.get("Status") != item["Status"]

                def _update(item=item, cert_id=cert_id):
                    table.update_item(
                        Key={"CertId": cert_id},
                        UpdateExpression="SET ExpiryDate = :expiry, #status = :status, LastDiscoveredAt = :discovered",
                        ExpressionAttributeNames={"#status": "Status"},
                        ExpressionAttributeValues={
                            ":expiry": item["ExpiryDate"],
                            ":status": item["Status"],
                            ":discovered": item["LastDiscoveredAt"],
                        },
                    )

                _with_retry(request_id, "EC2_DISCOVERY_UPDATE_FAILED", cert_id, _update)
                if changed:
                    updated_count += 1
                    action = "updated"
                else:
                    unchanged_count += 1
                    action = "unchanged"

            structured_log(
                request_id, "EC2_DISCOVERY_CERT_PROCESSED",
                certId=cert_id, domain=item.get("Domain"), expiryDate=item["ExpiryDate"],
                status=item["Status"], action=action,
            )
    except Exception as exc:
        _publish_error_metric(request_id)
        structured_log(
            request_id, "EC2_DISCOVERY_CYCLE_FAILED", level="ERROR",
            error=str(exc), newCerts=new_count, updatedCerts=updated_count, unchangedCerts=unchanged_count,
        )
        raise

    duration_ms = int((time.monotonic() - start) * 1000)
    structured_log(
        request_id, "EC2_DISCOVERY_CYCLE_COMPLETE",
        totalCertsFound=len(items), newCerts=new_count,
        updatedCerts=updated_count, unchangedCerts=unchanged_count,
        durationMs=duration_ms,
    )
    return {
        "instanceId": instance_id,
        "totalCertsFound": len(items),
        "newCerts": new_count,
        "updatedCerts": updated_count,
        "unchangedCerts": unchanged_count,
    }
