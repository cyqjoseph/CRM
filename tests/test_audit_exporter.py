import re
from unittest.mock import MagicMock, patch

from conftest import load_module

app = load_module("audit_exporter_app", "functions/audit_exporter/app.py")

KEY_PATTERN = re.compile(r"^[^/]+/\d{4}/\d{2}/\d{2}/.+-.+\.json$")


CERT_ARN = "arn:aws:acm:ap-southeast-1:123456789012:certificate/cert-1"


def _stream_event():
    return {
        "Records": [
            {
                "eventName": "INSERT",
                "dynamodb": {
                    "NewImage": {
                        "EntityId": {"S": CERT_ARN},
                        "EventTimestamp": {"S": "2026-08-31T12:00:00+00:00"},
                        "EventType": {"S": "EXPIRY_ALERT"},
                        "Outcome": {"S": "ALERTED"},
                    }
                },
            }
        ]
    }


@patch("boto3.client")
def test_s3_key_matches_entitytype_yyyy_mm_dd_entityid_eventtimestamp_pattern(mock_client):
    s3 = MagicMock()
    mock_client.return_value = s3

    result = app.handler(_stream_event(), None)

    assert result["exported"] == 1
    key = s3.put_object.call_args.kwargs["Key"]
    assert KEY_PATTERN.match(key), key
    assert key.startswith("cert/2026/08/31/")
    assert "cert-1" in key
