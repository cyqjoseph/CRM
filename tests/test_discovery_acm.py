from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from conftest import load_module

app = load_module("discovery_acm_app", "functions/discovery_acm/app.py")


def _paginator(pages):
    paginator = MagicMock()
    paginator.paginate.return_value = pages
    return paginator


@patch("boto3.resource")
@patch("boto3.client")
def test_never_writes_secret_or_private_key_fields(mock_client, mock_resource):
    acm = MagicMock()
    iam = MagicMock()
    secretsmanager = MagicMock()

    def client_side_effect(service_name, *a, **kw):
        return {"acm": acm, "iam": iam, "secretsmanager": secretsmanager}[service_name]

    mock_client.side_effect = client_side_effect

    acm.get_paginator.return_value = _paginator(
        [{"CertificateSummaryList": [{"CertificateArn": "arn:aws:acm:cert/1"}]}]
    )
    acm.describe_certificate.return_value = {
        "Certificate": {
            "CertificateArn": "arn:aws:acm:cert/1",
            "DomainName": "example.com",
            "NotAfter": datetime(2027, 1, 1, tzinfo=timezone.utc),
            "Status": "ISSUED",
            # A real ACM response never returns key material, but simulate an
            # attacker-controlled/buggy upstream field to prove the allow-list holds.
            "PrivateKey": "MALICIOUS",
            "SecretValue": "MALICIOUS",
        }
    }
    iam.get_paginator.return_value = _paginator([{"ServerCertificateMetadataList": []}])
    secretsmanager.get_paginator.return_value = _paginator([{"SecretList": []}])

    table = MagicMock()
    mock_resource.return_value.Table.return_value = table

    app.handler({}, None)

    assert table.put_item.called
    for call in table.put_item.call_args_list:
        item = call.kwargs["Item"]
        assert "SecretValue" not in item
        assert "PrivateKey" not in item
        assert set(item.keys()) <= app.ALLOWED_FIELDS


@patch("boto3.resource")
@patch("boto3.client")
def test_discovered_acm_certs_carry_the_domain_the_ui_renders(mock_client, mock_resource):
    """The Certificates table has its own Domain column.

    `Domain` was previously absent from ALLOWED_FIELDS and never set, so every
    discovered row rendered a blank Domain cell — a working discovery run that
    looked broken in the browser.
    """
    acm, iam, secretsmanager = MagicMock(), MagicMock(), MagicMock()

    def client_side_effect(name, *args, **kwargs):
        return {"acm": acm, "iam": iam, "secretsmanager": secretsmanager}[name]

    mock_client.side_effect = client_side_effect

    acm.get_paginator.return_value = _paginator(
        [{"CertificateSummaryList": [{"CertificateArn": "arn:aws:acm:cert/1"}]}]
    )
    acm.describe_certificate.return_value = {
        "Certificate": {
            "CertificateArn": "arn:aws:acm:cert/1",
            "DomainName": "payments.example.com",
            "NotAfter": datetime(2027, 1, 1, tzinfo=timezone.utc),
            "Status": "ISSUED",
        }
    }
    iam.get_paginator.return_value = _paginator([{"ServerCertificateMetadataList": []}])
    secretsmanager.get_paginator.return_value = _paginator([{"SecretList": []}])

    table = MagicMock()
    mock_resource.return_value.Table.return_value = table

    app.handler({}, None)

    item = table.put_item.call_args_list[0].kwargs["Item"]
    assert item["Domain"] == "payments.example.com"
    # Still never key material.
    assert "PrivateKey" not in item
