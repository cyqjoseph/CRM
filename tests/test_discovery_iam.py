from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from conftest import load_module

app = load_module("discovery_iam_app", "functions/discovery_iam/app.py")


def _iam_client(users_and_keys):
    """users_and_keys: list of (user_name, [(access_key_id, age_days, status), ...])"""
    iam = MagicMock()

    def get_paginator(op_name):
        paginator = MagicMock()
        if op_name == "list_users":
            paginator.paginate.return_value = [
                {"Users": [{"UserName": name, "Path": "/"} for name, _ in users_and_keys]}
            ]
        elif op_name == "list_access_keys":
            def paginate(UserName):
                for name, keys in users_and_keys:
                    if name == UserName:
                        now = datetime.now(timezone.utc)
                        metadata = [
                            {
                                "AccessKeyId": key_id,
                                "Status": status,
                                "CreateDate": now - timedelta(days=age_days),
                            }
                            for key_id, age_days, status in keys
                        ]
                        return [{"AccessKeyMetadata": metadata}]
                return [{"AccessKeyMetadata": []}]

            paginator.paginate.side_effect = paginate
        return paginator

    iam.get_paginator.side_effect = get_paginator
    return iam


@patch("boto3.resource")
@patch("boto3.client")
def test_active_keys_are_written_with_age_based_status(mock_client, mock_resource):
    mock_client.return_value = _iam_client(
        [
            ("svc-payments", [("AKIA1", 4, "Active")]),
            ("svc-reporting", [("AKIA2", 120, "Active")]),
            ("svc-backup", [("AKIA3", 200, "Active")]),
        ]
    )
    table = MagicMock()
    mock_resource.return_value.Table.return_value = table

    result = app.handler({}, None)

    assert result["discovered"] == 3
    assert result["written"] == 3
    statuses = {call.kwargs["Item"]["UserName"]: call.kwargs["Item"]["Status"] for call in table.put_item.call_args_list}
    assert statuses["svc-payments"] == "active"
    assert statuses["svc-reporting"] == "warning"
    assert statuses["svc-backup"] == "critical"


@patch("boto3.resource")
@patch("boto3.client")
def test_inactive_keys_are_skipped(mock_client, mock_resource):
    mock_client.return_value = _iam_client(
        [("svc-disabled", [("AKIA4", 10, "Inactive")])]
    )
    table = MagicMock()
    mock_resource.return_value.Table.return_value = table

    result = app.handler({}, None)

    assert result["discovered"] == 0
    assert result["written"] == 0
    table.put_item.assert_not_called()


@patch("boto3.resource")
@patch("boto3.client")
def test_written_items_never_store_the_raw_access_key_id(mock_client, mock_resource):
    mock_client.return_value = _iam_client([("svc-payments", [("AKIA-SECRET-ID", 4, "Active")])])
    table = MagicMock()
    mock_resource.return_value.Table.return_value = table

    app.handler({}, None)

    item = table.put_item.call_args.kwargs["Item"]
    assert "AKIA-SECRET-ID" not in json_dumps_safe(item)
    assert item["Source"] == "AWS_IAM"
    assert item["EnvironmentTag"] == "aws"
    assert "LastSyncedAt" in item


def json_dumps_safe(item):
    return "".join(f"{k}={v}" for k, v in item.items())
