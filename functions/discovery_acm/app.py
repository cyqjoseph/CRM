"""discovery-acm-fn: scans ACM/Secrets Manager/IAM for certificate metadata.

Writes ONLY lifecycle metadata to the cert inventory table. Must never persist
plaintext certificate or private key material (Requirement 1.4).
"""
import logging
import os
import time
from datetime import datetime, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

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


def _discover_acm_certs(acm_client, request_id):
    items = []
    paginator = acm_client.get_paginator("list_certificates")
    for page in paginator.paginate():
        summaries = page.get("CertificateSummaryList", [])
        logger.info("[%s] acm:ListCertificates page returned %d certificate(s)", request_id, len(summaries))
        for summary in summaries:
            arn = summary["CertificateArn"]
            try:
                detail = acm_client.describe_certificate(CertificateArn=arn)
            except Exception:
                logger.exception("[%s] acm:DescribeCertificate failed for %s", request_id, arn)
                continue
            cert = detail["Certificate"]
            logger.info(
                "[%s] acm:DescribeCertificate ok for %s domain=%s status=%s",
                request_id,
                arn,
                cert.get("DomainName"),
                cert.get("Status"),
            )
            items.append(
                {
                    "CertId": cert["CertificateArn"],
                    "CertType": "ACM",
                    "OwnerId": cert.get("DomainName", "unknown"),
                    "Domain": cert.get("DomainName", ""),
                    "ExpiryDate": cert.get("NotAfter").isoformat() if cert.get("NotAfter") else None,
                    "Status": cert.get("Status", "UNKNOWN"),
                    "Source": "acm",
                    "EnvironmentTag": "aws",
                }
            )
    return items


def _discover_iam_server_certs(iam_client, request_id):
    items = []
    paginator = iam_client.get_paginator("list_server_certificates")
    for page in paginator.paginate():
        metas = page.get("ServerCertificateMetadataList", [])
        logger.info("[%s] iam:ListServerCertificates page returned %d certificate(s)", request_id, len(metas))
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
        logger.info("[%s] secretsmanager:ListSecrets page returned %d secret(s)", request_id, len(secrets))
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
    (_discover_acm_certs, "acm", "acm"),
    (_discover_iam_server_certs, "iam", "iam"),
    (_discover_secrets_manager_certs, "secretsmanager", "secretsmanager"),
)


def handler(event, context):
    request_id = getattr(context, "aws_request_id", "local")
    logger.info("[%s] discovery-acm-fn starting", request_id)

    clients = {
        "acm": boto3.client("acm"),
        "iam": boto3.client("iam"),
        "secretsmanager": boto3.client("secretsmanager"),
    }
    table = boto3.resource("dynamodb").Table(CERT_TABLE_NAME)

    discovered = []
    for discover_fn, client_key, source_name in _DISCOVERERS:
        try:
            found = discover_fn(clients[client_key], request_id)
        except Exception:
            # One resource type's API call (e.g. AccessDenied on
            # iam:ListServerCertificates) must never prevent the others from
            # being discovered and written — a partial scan beats a silent
            # empty one.
            logger.exception("[%s] %s discovery failed", request_id, source_name)
            continue
        logger.info("[%s] %s discovery found %d item(s)", request_id, source_name, len(found))
        discovered.extend(found)

    written = 0
    failed = 0
    for raw_item in discovered:
        item = _sanitize(raw_item)
        item["Version"] = int(time.time())
        item["LastSyncedAt"] = datetime.now(timezone.utc).isoformat()
        try:
            table.put_item(Item=item)
        except Exception:
            failed += 1
            logger.exception("[%s] dynamodb:PutItem failed for CertId=%s", request_id, item.get("CertId"))
            continue
        written += 1
        logger.info("[%s] dynamodb:PutItem ok for CertId=%s", request_id, item.get("CertId"))

    logger.info(
        "[%s] discovery-acm-fn complete discovered=%d written=%d failed=%d",
        request_id,
        len(discovered),
        written,
        failed,
    )
    return {"discovered": len(discovered), "written": written, "failed": failed}
