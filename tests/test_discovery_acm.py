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


@patch("boto3.resource")
@patch("boto3.client")
def test_describe_certificate_failure_does_not_block_other_certs(mock_client, mock_resource):
    """A bad DescribeCertificate call for one ARN must not drop every other
    discoverable certificate — this is the "discovery ran but the table stayed
    empty" failure mode: one AccessDenied/ResourceNotFound on a single cert used
    to abort the whole handler before anything was written."""
    acm, iam, secretsmanager = MagicMock(), MagicMock(), MagicMock()

    def client_side_effect(name, *args, **kwargs):
        return {"acm": acm, "iam": iam, "secretsmanager": secretsmanager}[name]

    mock_client.side_effect = client_side_effect

    acm.get_paginator.return_value = _paginator(
        [
            {
                "CertificateSummaryList": [
                    {"CertificateArn": "arn:aws:acm:cert/broken"},
                    {"CertificateArn": "arn:aws:acm:cert/good"},
                ]
            }
        ]
    )

    def describe_side_effect(CertificateArn):
        if CertificateArn == "arn:aws:acm:cert/broken":
            raise Exception("AccessDenied")
        return {
            "Certificate": {
                "CertificateArn": CertificateArn,
                "DomainName": "good.example.com",
                "NotAfter": datetime(2027, 1, 1, tzinfo=timezone.utc),
                "Status": "ISSUED",
            }
        }

    acm.describe_certificate.side_effect = describe_side_effect
    iam.get_paginator.return_value = _paginator([{"ServerCertificateMetadataList": []}])
    secretsmanager.get_paginator.return_value = _paginator([{"SecretList": []}])

    table = MagicMock()
    mock_resource.return_value.Table.return_value = table

    result = app.handler({}, None)

    assert result == {"discovered": 1, "written": 1, "failed": 0}
    item = table.put_item.call_args_list[0].kwargs["Item"]
    assert item["CertId"] == "arn:aws:acm:cert/good"


@patch("boto3.resource")
@patch("boto3.client")
def test_put_item_failure_is_logged_and_does_not_block_other_writes(mock_client, mock_resource):
    """A DynamoDB write failure (e.g. throttling, missing permission) for one
    item must not silently swallow the rest of the batch."""
    acm, iam, secretsmanager = MagicMock(), MagicMock(), MagicMock()

    def client_side_effect(name, *args, **kwargs):
        return {"acm": acm, "iam": iam, "secretsmanager": secretsmanager}[name]

    mock_client.side_effect = client_side_effect

    acm.get_paginator.return_value = _paginator(
        [
            {
                "CertificateSummaryList": [
                    {"CertificateArn": "arn:aws:acm:cert/1"},
                    {"CertificateArn": "arn:aws:acm:cert/2"},
                ]
            }
        ]
    )
    acm.describe_certificate.side_effect = lambda CertificateArn: {
        "Certificate": {
            "CertificateArn": CertificateArn,
            "DomainName": "example.com",
            "NotAfter": datetime(2027, 1, 1, tzinfo=timezone.utc),
            "Status": "ISSUED",
        }
    }
    iam.get_paginator.return_value = _paginator([{"ServerCertificateMetadataList": []}])
    secretsmanager.get_paginator.return_value = _paginator([{"SecretList": []}])

    table = MagicMock()
    table.put_item.side_effect = [Exception("ProvisionedThroughputExceededException"), None]
    mock_resource.return_value.Table.return_value = table

    result = app.handler({}, None)

    assert result == {"discovered": 2, "written": 1, "failed": 1}
    assert table.put_item.call_count == 2


@patch("boto3.resource")
@patch("boto3.client")
def test_one_failed_source_does_not_block_other_sources(mock_client, mock_resource):
    """iam:ListServerCertificates raising (e.g. AccessDenied) must not prevent
    ACM certificates from being discovered and written."""
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
            "DomainName": "example.com",
            "NotAfter": datetime(2027, 1, 1, tzinfo=timezone.utc),
            "Status": "ISSUED",
        }
    }
    iam.get_paginator.side_effect = Exception("AccessDenied")
    secretsmanager.get_paginator.return_value = _paginator([{"SecretList": []}])

    table = MagicMock()
    mock_resource.return_value.Table.return_value = table

    result = app.handler({}, None)

    assert result == {"discovered": 1, "written": 1, "failed": 0}
