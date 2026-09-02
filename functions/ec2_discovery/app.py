"""ec2-discovery-fn: discovers certificates from the cert-scanner EC2 instance
(see Ec2CertScannerInstance in template.yaml) and merges them into the cert
inventory table.

Two directories are scanned, and the distinction matters:

  * APP_CERT_DIR (/opt/app/certs) — the instance's own application certificates.
    Its UserData builds an internal CA at first boot, generates a private key and
    a CSR per service hostname, signs each CSR with that CA, and installs the
    signed leaf here. Those are the rows worth looking at on the dashboard:
    real X.509 certificates, with deliberately varied validity so the expiry
    bands and the alerting path both have something to act on.
  * SYSTEM_CERT_DIR (/etc/ssl/certs) — the OS trust store. Useful (a root CA
    does expire) but voluminous, so it is capped at SYSTEM_CERT_LIMIT.

Triggered every 30 minutes by Ec2DiscoveryScheduleRule. One SSM Run Command does
both the enumeration and the parsing: it lists the certificate files and, for
each, runs `openssl x509 -text` wrapped in file markers, so a single
SendCommand/GetCommandInvocation round trip yields every certificate's full text
in one stdout blob — avoiding one SSM round trip per certificate, which would not
fit this function's Lambda timeout.

Discovered rows are merged, never wholesale replaced: an existing CertId's
ExpiryDate/Status/LastDiscoveredAt are updated in place and a new CertId is
inserted. The one thing this function does delete is a row it wrote itself for an
EC2 instance that no longer exists — CertId hashes in the instance id, so a
replaced instance (any UserData change replaces it) would otherwise leave a
full set of orphans behind on every deploy.
"""
import hashlib
import os
import re
import time
from datetime import datetime, timezone

import boto3
import botocore.exceptions

from crm_common import SHARED_OWNER_ID, cert_status_for, structured_log

INSTANCE_ID_PARAM_NAME = os.environ["EC2_INSTANCE_ID_PARAM"]
CERT_TABLE_NAME = os.environ["CERT_TABLE"]
# The shared team partition — every CRM login reads it. A per-login OwnerId here
# is what made these rows invisible to everybody: GET /certs queries OwnerIndex,
# and this function has no Cognito sub to write.
OWNER_ID = os.environ.get("OWNER_ID") or SHARED_OWNER_ID

APP_CERT_DIR = os.environ.get("APP_CERT_DIR", "/opt/app/certs")
SYSTEM_CERT_DIR = os.environ.get("SYSTEM_CERT_DIR", "/etc/ssl/certs")
# The Ubuntu trust store holds ~140 roots. Storing all of them buries the
# application certificates the dashboard exists to show, so cap it.
SYSTEM_CERT_LIMIT = int(os.environ.get("SYSTEM_CERT_LIMIT", "50"))

SOURCE_NAME = "ec2-os-certs"
CERT_TYPE_APP = "EC2_APP_CERT"
CERT_TYPE_SYSTEM_CA = "EC2_SYSTEM_CA"
COMMAND_POLL_INTERVAL_SECONDS = 2
COMMAND_POLL_BUDGET_SECONDS = 20
DYNAMODB_MAX_RETRIES = 3
DYNAMODB_RETRY_BASE_DELAY_SECONDS = 0.5


def build_scan_command(app_dir=None, system_dir=None, system_limit=None):
    """The shell the SSM Run Command executes on the instance.

    Each certificate's full `openssl x509 -text` output is wrapped in markers
    naming its path, so one stdout blob can be split back into per-file blocks
    and each block classified by the directory it came from.

    The application directory is enumerated first and in full — it is small, and
    those are the rows that matter. The trust store follows, capped, so a
    hundred-odd root CAs cannot crowd out the application certificates or
    overrun the command's output limit.
    """
    app_dir = app_dir or APP_CERT_DIR
    system_dir = system_dir or SYSTEM_CERT_DIR
    system_limit = SYSTEM_CERT_LIMIT if system_limit is None else system_limit

    # -L follows the per-certificate symlinks Ubuntu populates /etc/ssl/certs
    # with; without it `-type f` matches almost nothing there.
    listings = [f'find -L {app_dir} -name "*.pem" -o -name "*.crt" 2>/dev/null']
    if system_limit > 0:
        listings.append(
            f'find -L {system_dir} -name "*.pem" -type f 2>/dev/null | head -{system_limit}'
        )

    return (
        "for f in $(" + "; ".join(listings) + "); do "
        '[ -f "$f" ] || continue; '
        'echo "===CERT_FILE_START:$f==="; '
        'openssl x509 -in "$f" -text -noout -nameopt RFC2253 2>/dev/null '
        '|| echo "===CERT_PARSE_ERROR:$f==="; '
        'echo "===CERT_FILE_END:$f==="; '
        "done"
    )


# Kept for callers/tests that want the default command without arguments.
CERT_SCAN_COMMAND = build_scan_command()

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
    """ISSUED or EXPIRED — the same vocabulary every other writer uses.

    This function used to emit "active"/"expiring-soon"/"expired". `Status` is
    ExpiryIndex's HASH key and expiry-evaluator-fn queries it with the literal
    "ISSUED", so those rows were silently excluded from every expiry alert while
    looking perfectly healthy in the table, and sat in the UI next to seeded rows
    reading "ISSUED" as if they were a different kind of thing. "Expiring soon"
    is not a status, it is a distance from today — the dashboard computes it from
    ExpiryDate and colours the row accordingly.
    """
    return cert_status_for(expiry_dt, now)


def _classify_cert_type(issuer_dn, path=None):
    """EC2_APP_CERT for the instance's own application certificates,
    EC2_SYSTEM_CA for the OS trust store.

    The directory is authoritative when known: an application certificate signed
    by an internal CA whose name happens to contain a public CA's brand would
    otherwise be filed as a system root. The issuer heuristic remains the
    fallback for a certificate found outside either known directory.
    """
    if path:
        if path.startswith(APP_CERT_DIR):
            return CERT_TYPE_APP
        if path.startswith(SYSTEM_CERT_DIR):
            return CERT_TYPE_SYSTEM_CA
    if not issuer_dn:
        return CERT_TYPE_APP
    lowered = issuer_dn.lower()
    return CERT_TYPE_SYSTEM_CA if any(m in lowered for m in _KNOWN_ROOT_CA_MARKERS) else CERT_TYPE_APP


def _build_cert_item(block, instance_id, now, path=None):
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
        "CertType": _classify_cert_type(issuer_dn, path),
        # Which instance this came from, so a row left behind by a replaced
        # instance can be recognised and pruned — see _prune_stale_instances.
        "InstanceId": instance_id,
        "CertPath": path,
        "EnvironmentTag": "aws",
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
                Parameters={"commands": [build_scan_command()]},
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


def _prune_stale_instances(table, existing, instance_id, request_id):
    """Delete rows this function wrote for an EC2 instance that no longer exists.

    CertId is a hash of (serial, instance id), so the same certificate on a
    replaced instance is a different row. Any UserData or AMI change replaces the
    instance, which without this leaves a complete set of orphaned certificates
    behind on every deploy — rows that look real, never update again, and drift
    into "expired" while nothing on the dashboard explains why.

    Scoped tightly: only rows whose Source is this function's own, and only those
    carrying a different InstanceId. A row with no InstanceId at all predates that
    attribute and is left alone rather than guessed about.
    """
    stale = [
        cert_id for cert_id, item in existing.items()
        if item.get("InstanceId") and item["InstanceId"] != instance_id
    ]
    pruned = 0
    for cert_id in stale:
        try:
            table.delete_item(Key={"CertId": cert_id})
        except Exception as exc:
            structured_log(
                request_id, "EC2_DISCOVERY_PRUNE_FAILED", level="WARNING",
                certId=cert_id, error=str(exc),
            )
            continue
        existing.pop(cert_id, None)
        pruned += 1
        structured_log(request_id, "EC2_DISCOVERY_PRUNED_STALE_INSTANCE_ROW", certId=cert_id)
    return pruned


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
                item = _build_cert_item(block, instance_id, now, path=path)
            except Exception as exc:
                structured_log(request_id, "EC2_DISCOVERY_CERT_PARSE_FAILED", level="WARNING", path=path, error=str(exc))
        if item is None:
            if block is not None:
                structured_log(request_id, "EC2_DISCOVERY_CERT_PARSE_FAILED", level="WARNING", path=path)
            continue
        items.append(item)

    app_cert_count = sum(1 for i in items if i["CertType"] == CERT_TYPE_APP)
    structured_log(
        request_id, "EC2_DISCOVERY_PARSED",
        totalCertsFound=len(items), appCerts=app_cert_count,
        systemCas=len(items) - app_cert_count,
    )
    if not app_cert_count:
        # The instance's UserData generates and signs these at first boot, so an
        # empty application directory means either the boot script has not
        # finished yet (this runs minutes after deploy) or it failed. Worth saying
        # out loud: the trust store alone still yields rows, which otherwise makes
        # a broken certificate-issuing step look like a successful scan.
        structured_log(
            request_id, "EC2_DISCOVERY_NO_APP_CERTS", level="WARNING",
            appCertDir=APP_CERT_DIR, instanceId=instance_id,
        )

    table = boto3.resource("dynamodb").Table(CERT_TABLE_NAME)
    try:
        existing = _existing_certs_by_id(table, OWNER_ID)
    except Exception as exc:
        structured_log(request_id, "EC2_DISCOVERY_QUERY_FAILED", level="ERROR", error=str(exc))
        existing = {}

    pruned_count = _prune_stale_instances(table, existing, instance_id, request_id)

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
                    # CertType/InstanceId are set here too, not just on insert:
                    # rows written before those attributes existed (or under the
                    # old "active"/"expiring-soon" status vocabulary) are
                    # corrected in place on the next cycle rather than staying
                    # wrong until someone deletes them.
                    table.update_item(
                        Key={"CertId": cert_id},
                        UpdateExpression=(
                            "SET ExpiryDate = :expiry, #status = :status, "
                            "LastDiscoveredAt = :discovered, CertType = :certType, "
                            "InstanceId = :instanceId, OwnerId = :ownerId"
                        ),
                        ExpressionAttributeNames={"#status": "Status"},
                        ExpressionAttributeValues={
                            ":expiry": item["ExpiryDate"],
                            ":status": item["Status"],
                            ":discovered": item["LastDiscoveredAt"],
                            ":certType": item["CertType"],
                            ":instanceId": item["InstanceId"],
                            ":ownerId": item["OwnerId"],
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
        totalCertsFound=len(items), appCerts=app_cert_count, newCerts=new_count,
        updatedCerts=updated_count, unchangedCerts=unchanged_count,
        prunedCerts=pruned_count, durationMs=duration_ms,
    )
    return {
        "instanceId": instance_id,
        "totalCertsFound": len(items),
        "appCerts": app_cert_count,
        "newCerts": new_count,
        "updatedCerts": updated_count,
        "unchangedCerts": unchanged_count,
        "prunedCerts": pruned_count,
    }
