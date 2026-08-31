from conftest import load_module

app = load_module("rotation_iam_key_app", "functions/rotation_iam_key/app.py")


def test_handler_flags_the_account_without_calling_any_aws_api():
    result = app.handler({"accountIdHash": "hash-1"}, None)

    assert result["accountIdHash"] == "hash-1"
    assert result["mode"] == "NOTIFY_ONLY"
    assert "flaggedAt" in result
