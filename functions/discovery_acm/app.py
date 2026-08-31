"""discovery-acm-fn: scans ACM/Secrets Manager/IAM for certificate metadata.

Writes ONLY lifecycle metadata to the cert inventory table. Must never persist
plaintext certificate or private key material (Requirement 1.4).
"""
import os
import time

import boto3

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
}


def _sanitize(item):
    return {k: v for k, v in item.items() if k in ALLOWED_FIELDS}


def _discover_acm_certs(acm_client):
    items = []
    paginator = acm_client.get_paginator("list_certificates")
    for page in paginator.paginate():
        for summary in page.get("CertificateSummaryList", []):
            detail = acm_client.describe_certificate(CertificateArn=summary["CertificateArn"])
            cert = detail["Certificate"]
            items.append(
                {
                    "CertId": cert["CertificateArn"],
                    "CertType": "ACM",
                    "OwnerId": cert.get("DomainName", "unknown"),
                    "Domain": cert.get("DomainName", ""),
                    "ExpiryDate": cert.get("NotAfter").isoformat() if cert.get("NotAfter") else None,
                    "Status": cert.get("Status", "UNKNOWN"),
                    "Source": "acm",
                }
            )
    return items


def _discover_iam_server_certs(iam_client):
    items = []
    paginator = iam_client.get_paginator("list_server_certificates")
    for page in paginator.paginate():
        for meta in page.get("ServerCertificateMetadataList", []):
            items.append(
                {
                    "CertId": meta["Arn"],
                    "CertType": "IAM_SERVER_CERT",
                    "OwnerId": meta.get("Path", "/"),
                    "ExpiryDate": meta.get("Expiration").isoformat() if meta.get("Expiration") else None,
                    "Status": "ISSUED",
                    "Source": "iam",
                }
            )
    return items


def _discover_secrets_manager_certs(secretsmanager_client):
    """Secrets Manager entries tagged as certificates: metadata only, never the secret value."""
    items = []
    paginator = secretsmanager_client.get_paginator("list_secrets")
    for page in paginator.paginate(
        Filters=[{"Key": "tag-key", "Values": ["crm:resource-type"]}]
    ):
        for secret in page.get("SecretList", []):
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
                }
            )
    return items


def handler(event, context):
    acm = boto3.client("acm")
    iam = boto3.client("iam")
    secretsmanager = boto3.client("secretsmanager")
    table = boto3.resource("dynamodb").Table(CERT_TABLE_NAME)

    discovered = (
        _discover_acm_certs(acm)
        + _discover_iam_server_certs(iam)
        + _discover_secrets_manager_certs(secretsmanager)
    )

    written = 0
    for raw_item in discovered:
        item = _sanitize(raw_item)
        item["Version"] = int(time.time())
        table.put_item(Item=item)
        written += 1

    return {"discovered": len(discovered), "written": written}
