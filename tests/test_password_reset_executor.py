import json
from unittest.mock import MagicMock, patch

from conftest import load_module

app = load_module("password_reset_executor_app", "functions/password_reset_executor/app.py")


@patch("boto3.client")
def test_generates_a_temporary_password_and_never_returns_it(mock_client):
    sm = MagicMock()
    sm.get_secret_value.return_value = {"SecretString": "{}"}
    mock_client.return_value = sm

    result = app.handler({"requestId": "r1", "accountId": "hash-1", "timestamp": "ts-1"}, None)

    assert result == {"requestId": "r1", "accountId": "hash-1", "timestamp": "ts-1"}
    assert "password" not in json.dumps(result).lower()


@patch("boto3.client")
def test_stores_only_a_hash_and_metadata_in_secrets_manager_never_plaintext(mock_client):
    sm = MagicMock()
    sm.get_secret_value.return_value = {"SecretString": "{}"}
    mock_client.return_value = sm

    app.handler({"requestId": "r1", "accountId": "hash-1", "timestamp": "ts-1"}, None)

    put_kwargs = sm.put_secret_value.call_args.kwargs
    stored = json.loads(put_kwargs["SecretString"])
    assert "r1" in stored
    entry = stored["r1"]
    assert entry["accountId"] == "hash-1"
    assert "passwordHash" in entry and len(entry["passwordHash"]) == 64  # sha256 hex digest
    assert "password" not in entry  # no plaintext field at all


@patch("boto3.client")
def test_preserves_previously_stored_entries_for_other_requests(mock_client):
    sm = MagicMock()
    sm.get_secret_value.return_value = {
        "SecretString": json.dumps({"r0": {"accountId": "hash-0", "passwordHash": "a" * 64}})
    }
    mock_client.return_value = sm

    app.handler({"requestId": "r1", "accountId": "hash-1", "timestamp": "ts-1"}, None)

    put_kwargs = sm.put_secret_value.call_args.kwargs
    stored = json.loads(put_kwargs["SecretString"])
    assert set(stored) == {"r0", "r1"}


@patch("boto3.client")
def test_raises_on_failure_instead_of_swallowing(mock_client):
    """Step Functions Retry/Catch relies on this raising, like rotation_iam_key."""
    sm = MagicMock()
    sm.get_secret_value.side_effect = RuntimeError("Secrets Manager exploded")
    mock_client.return_value = sm

    try:
        app.handler({"requestId": "r1", "accountId": "hash-1", "timestamp": "ts-1"}, None)
        assert False, "expected the handler to raise"
    except RuntimeError:
        pass
