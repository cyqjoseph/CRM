"""discovery-acm-fn: IAM server certificates + tagged Secrets Manager entries.

This function used to scan ACM as a third source. It no longer does, and the
first test here is what keeps it that way: ACM is absent from CLAUDE.md's
allowed-services list, so the account permissions boundary denies
acm:ListCertificates whatever the function's own role grants. The branch could
only ever log one AccessDeniedException per run.
"""
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from conftest import load_module

app = load_module("discovery_acm_app", "functions/discovery_acm/app.py")


def _paginator(pages):
    paginator = MagicMock()
    paginator.paginate.return_value = pages
    return paginator


def _clients(mock_client, iam_pages=None, secret_pages=None):
    """Wire boto3.client to per-service mocks and return them."""
    iam, secretsmanager = MagicMock(), MagicMock()
    iam.get_paginator.return_value = _paginator(
        iam_pages if iam_pages is not None else [{"ServerCertificateMetadataList": []}]
    )
    secretsmanager.get_paginator.return_value = _paginator(
        secret_pages if secret_pages is not None else [{"SecretList": []}]
    )

    def side_effect(service_name, *args, **kwargs):
        # A KeyError here is the point: it means the handler asked for a client
        # it should no longer construct (e.g. "acm").
        return {"iam": iam, "secretsmanager": secretsmanager}[service_name]

    mock_client.side_effect = side_effect
    return iam, secretsmanager


def _server_cert(arn, expiration=None, path="/prod/"):
    return {
        "Arn": arn,
        "Path": path,
        "Expiration": expiration or datetime(2027, 1, 1, tzinfo=timezone.utc),
    }


@patch("boto3.resource")
@patch("boto3.client")
def test_acm_is_never_called(mock_client, mock_resource):
    """The permissions boundary denies acm:* — the branch must stay gone.

    Reintroducing it makes every run log an AccessDeniedException and, worse,
    tempts a future reader into "fixing" the IAM policy, which cannot work.
    """
    _clients(mock_client)
    mock_resource.return_value.Table.return_value = MagicMock()

    app.handler({}, None)

    requested = [call.args[0] for call in mock_client.call_args_list if call.args]
    assert "acm" not in requested, f"handler constructed an ACM client: {requested}"
    assert "acm" not in [key for fn, key, _ in app._DISCOVERERS]


@patch("boto3.resource")
@patch("boto3.client")
def test_never_writes_secret_or_private_key_fields(mock_client, mock_resource):
    """Simulate a buggy/hostile upstream field to prove the allow-list holds."""
    iam, secretsmanager = _clients(
        mock_client,
        secret_pages=[
            {
                "SecretList": [
                    {
                        "ARN": "arn:aws:secretsmanager:secret/1",
                        "Tags": [
                            {"Key": "crm:resource-type", "Value": "certificate"},
                            {"Key": "crm:owner-id", "Value": "team-payments"},
                            {"Key": "crm:expiry-date", "Value": "2027-01-01"},
                            # Neither of these may ever reach DynamoDB.
                            {"Key": "PrivateKey", "Value": "MALICIOUS"},
                        ],
                    }
                ]
            }
        ],
    )

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
def test_iam_server_certs_are_discovered_and_written(mock_client, mock_resource):
    _clients(
        mock_client,
        iam_pages=[{"ServerCertificateMetadataList": [_server_cert("arn:aws:iam:cert/1")]}],
    )

    table = MagicMock()
    mock_resource.return_value.Table.return_value = table

    result = app.handler({}, None)

    assert result == {"discovered": 1, "written": 1, "skipped": 0, "failed": 0}
    item = table.put_item.call_args_list[0].kwargs["Item"]
    assert item["CertId"] == "arn:aws:iam:cert/1"
    assert item["CertType"] == "IAM_SERVER_CERT"
    assert item["ExpiryDate"] == "2027-01-01T00:00:00+00:00"


@patch("boto3.resource")
@patch("boto3.client")
def test_one_failed_source_does_not_block_other_sources(mock_client, mock_resource):
    """iam:ListServerCertificates raising (e.g. AccessDenied) must not prevent
    the Secrets Manager source from being discovered and written."""
    iam, secretsmanager = _clients(
        mock_client,
        secret_pages=[
            {
                "SecretList": [
                    {
                        "ARN": "arn:aws:secretsmanager:secret/1",
                        "Tags": [{"Key": "crm:resource-type", "Value": "certificate"}],
                    }
                ]
            }
        ],
    )
    iam.get_paginator.side_effect = Exception("AccessDenied")

    table = MagicMock()
    mock_resource.return_value.Table.return_value = table

    result = app.handler({}, None)

    assert result == {"discovered": 1, "written": 1, "skipped": 0, "failed": 0}


@patch("boto3.resource")
@patch("boto3.client")
def test_put_item_failure_is_logged_and_does_not_block_other_writes(mock_client, mock_resource):
    """A DynamoDB write failure (throttling, missing permission) for one item
    must not silently swallow the rest of the batch."""
    _clients(
        mock_client,
        iam_pages=[
            {
                "ServerCertificateMetadataList": [
                    _server_cert("arn:aws:iam:cert/1"),
                    _server_cert("arn:aws:iam:cert/2"),
                ]
            }
        ],
    )

    table = MagicMock()
    table.put_item.side_effect = [Exception("ProvisionedThroughputExceededException"), None]
    mock_resource.return_value.Table.return_value = table

    result = app.handler({}, None)

    assert result == {"discovered": 2, "written": 1, "skipped": 0, "failed": 1}
    assert table.put_item.call_count == 2


@patch("boto3.resource")
@patch("boto3.client")
def test_write_is_conditional_on_a_newer_version_and_stale_writes_are_skipped_not_failed(
    mock_client, mock_resource
):
    """A duplicate/retried invocation racing an already-written newer row must
    be treated as an idempotent no-op, not counted as a failure."""
    import botocore.exceptions

    _clients(
        mock_client,
        iam_pages=[{"ServerCertificateMetadataList": [_server_cert("arn:aws:iam:cert/1")]}],
    )

    table = MagicMock()
    table.put_item.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ConditionalCheckFailedException", "Message": "stale"}},
        "PutItem",
    )
    mock_resource.return_value.Table.return_value = table

    result = app.handler({}, None)

    assert result == {"discovered": 1, "written": 0, "skipped": 1, "failed": 0}
    kwargs = table.put_item.call_args.kwargs
    assert kwargs["ConditionExpression"] == "attribute_not_exists(#v) OR #v < :new_version"
    assert kwargs["ExpressionAttributeNames"] == {"#v": "Version"}
    assert ":new_version" in kwargs["ExpressionAttributeValues"]
