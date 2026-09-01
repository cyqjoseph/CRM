"""discovery-certs-fn: scans IAM server certificates and Secrets Manager for
certificate metadata.

Writes ONLY lifecycle metadata to the cert inventory table. Must never persist
plaintext certificate or private key material (Requirement 1.4).

Does NOT scan ACM. ACM is absent from CLAUDE.md's exhaustive allowed-services
list, so the account permissions boundary denies acm:ListCertificates no matter
what this function's own role grants — the branch could only ever log
AccessDeniedException once per run. See README.md's Deviations section.
"""
import os
import time
from datetime import datetime, timezone

import boto3
import botocore.exceptions

from crm_common import structured_log

CERT_TABLE_NAME = os.environ["CERT_TABLE_NAME"]

# Fields we are allowed to write. Anything not in this allow-list is dropped
# before the PutItem call, so a code change elsewhere can never smuggle a
# plaintext secret field (e.g. SecretValue/PrivateKey) into the table.
# `Domain` is lifecycle metadata, not key material, and the UI renders it as its
# own column — without it every discovered row shows a blank Domain cell.
ALLOWED_FIELDS = {
    "CertId",
    "CertType",
    "OwnerId",
    "Domain",
    "ExpiryDate",
    "Status",
    "Source",
    "Version",
    "EnvironmentTag",
    "LastSyncedAt",
}


def _sanitize(item):
    return {k: v for k, v in item.items() if k in ALLOWED_FIELDS}


def _discover_iam_server_certs(iam_client, request_id):
    items = []
    paginator = iam_client.get_paginator("list_server_certificates")
    for page in paginator.paginate():
        metas = page.get("ServerCertificateMetadataList", [])
        structured_log(request_id, "IAM_LIST_PAGE", source="iam", count=len(metas))
        for meta in metas:
            items.append(
                {
                    "CertId": meta["Arn"],
                    "CertType": "IAM_SERVER_CERT",
                    "OwnerId": meta.get("Path", "/"),
                    "ExpiryDate": meta.get("Expiration").isoformat() if meta.get("Expiration") else None,
                    "Status": "ISSUED",
                    "Source": "iam",
                    "EnvironmentTag": "aws",
                }
            )
    return items


def _discover_secrets_manager_certs(secretsmanager_client, request_id):
    """Secrets Manager entries tagged as certificates: metadata only, never the secret value."""
    items = []
    paginator = secretsmanager_client.get_paginator("list_secrets")
    for page in paginator.paginate(
        Filters=[{"Key": "tag-key", "Values": ["crm:resource-type"]}]
    ):
        secrets = page.get("SecretList", [])
        structured_log(request_id, "SECRETSMANAGER_LIST_PAGE", source="secretsmanager", count=len(secrets))
        for secret in secrets:
            tags = {t["Key"]: t["Value"] for t in secret.get("Tags", [])}
            if tags.get("crm:resource-type") != "certificate":
                continue
            items.append(
                {
                    "CertId": secret["ARN"],
                    "CertType": "SELF_SIGNED",
                    "OwnerId": tags.get("crm:owner-id", "unknown"),
                    "ExpiryDate": tags.get("crm:expiry-date"),
                    "Status": "ISSUED",
                    "Source": "secretsmanager",
                    "EnvironmentTag": "aws",
                }
            )
    return items


# (discovery function, client key, human-readable source name)
_DISCOVERERS = (
    (_discover_iam_server_certs, "iam", "iam"),
    (_discover_secrets_manager_certs, "secretsmanager", "secretsmanager"),
)


def _is_conditional_check_failure(exc):
    return (
        isinstance(exc, botocore.exceptions.ClientError)
        and exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException"
    )


def handler(event, context):
    request_id = getattr(context, "aws_request_id", "local")
    structured_log(request_id, "DISCOVERY_CERTS_START")

    clients = {
        "iam": boto3.client("iam"),
        "secretsmanager": boto3.client("secretsmanager"),
    }
    table = boto3.resource("dynamodb").Table(CERT_TABLE_NAME)

    discovered = []
    for discover_fn, client_key, source_name in _DISCOVERERS:
        try:
            found = discover_fn(clients[client_key], request_id)
        except Exception as exc:
            # One resource type's API call (e.g. AccessDenied on
            # iam:ListServerCertificates) must never prevent the others from
            # being discovered and written — a partial scan beats a silent
            # empty one.
            structured_log(request_id, "DISCOVERY_SOURCE_FAILED", level="ERROR", source=source_name, error=str(exc))
            continue
        structured_log(request_id, "DISCOVERY_SOURCE_OK", source=source_name, count=len(found))
        discovered.extend(found)

    written = 0
    skipped = 0
    failed = 0
    for raw_item in discovered:
        item = _sanitize(raw_item)
        version = int(time.time())
        item["Version"] = version
        item["LastSyncedAt"] = datetime.now(timezone.utc).isoformat()
        try:
            # Conditional write: only overwrite if this row is new or this
            # Version is newer than what's already stored — guards against a
            # retried/duplicate invocation clobbering a newer write with stale
            # data (idempotency per Requirement's "version attribute").
            table.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(#v) OR #v < :new_version",
                ExpressionAttributeNames={"#v": "Version"},
                ExpressionAttributeValues={":new_version": version},
            )
        except Exception as exc:
            if _is_conditional_check_failure(exc):
                skipped += 1
                structured_log(request_id, "DISCOVERY_WRITE_SKIPPED_STALE", certId=item.get("CertId"))
                continue
            failed += 1
            structured_log(request_id, "DISCOVERY_WRITE_FAILED", level="ERROR", certId=item.get("CertId"), error=str(exc))
            continue
        written += 1
        structured_log(request_id, "DISCOVERY_WRITE_OK", certId=item.get("CertId"))

    structured_log(
        request_id,
        "DISCOVERY_CERTS_COMPLETE",
        discovered=len(discovered),
        written=written,
        skipped=skipped,
        failed=failed,
    )
    return {"discovered": len(discovered), "written": written, "skipped": skipped, "failed": failed}
