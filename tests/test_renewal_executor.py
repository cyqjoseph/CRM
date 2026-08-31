from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from conftest import load_module

app = load_module("renewal_executor_app", "functions/renewal_executor/app.py")


@patch("boto3.resource")
@patch("boto3.client")
def test_update_item_never_receives_secret_or_private_key_fields(mock_client, mock_resource):
    acm = MagicMock()
    mock_client.return_value = acm
    acm.describe_certificate.return_value = {
        "Certificate": {
            "NotAfter": datetime(2027, 1, 1, tzinfo=timezone.utc),
            "Status": "ISSUED",
            "PrivateKey": "MALICIOUS",
            "Secret": "MALICIOUS",
        }
    }

    table = MagicMock()
    mock_resource.return_value.Table.return_value = table

    result = app.handler({"certId": "cert-1", "certArn": "arn:aws:acm:cert/1"}, None)

    acm.renew_certificate.assert_called_once_with(CertificateArn="arn:aws:acm:cert/1")
    assert table.update_item.called
    kwargs = table.update_item.call_args.kwargs
    values = kwargs["ExpressionAttributeValues"]
    names = kwargs["ExpressionAttributeNames"]
    assert not any("secret" in v.lower() for v in values.values() if isinstance(v, str))
    assert all(n.lstrip("#") in app.ALLOWED_UPDATE_FIELDS for n in names.values())
    assert result["status"] == "ISSUED"
