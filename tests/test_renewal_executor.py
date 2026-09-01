"""renewal-executor-fn: records a renewal against the inventory row.

The Renew button's whole failure mode lived here. The function used to call
acm:RenewCertificate, which the account permissions boundary denies (ACM is not
in CLAUDE.md's allowed-services list). The API still returned 202 the moment the
state machine started, so the browser showed "Renewal started" and the real
AccessDeniedException only ever appeared in the execution history.
"""
from datetime import date, timedelta
from unittest.mock import MagicMock, patch

from conftest import load_module

app = load_module("renewal_executor_app", "functions/renewal_executor/app.py")


@patch("boto3.resource")
@patch("boto3.client")
def test_no_acm_call_is_ever_made(mock_client, mock_resource):
    """Regression guard for the boundary-denied call that broke every renewal."""
    mock_resource.return_value.Table.return_value = MagicMock()

    app.handler({"certId": "cert-1"}, None)

    requested = [call.args[0] for call in mock_client.call_args_list if call.args]
    assert "acm" not in requested, f"handler constructed an ACM client: {requested}"
    assert not mock_client.called, "this function needs no boto3 client at all"


@patch("boto3.resource")
def test_expiry_is_extended_and_status_reset_to_issued(mock_resource):
    table = MagicMock()
    mock_resource.return_value.Table.return_value = table

    result = app.handler({"certId": "cert-1"}, None)

    assert table.update_item.called
    kwargs = table.update_item.call_args.kwargs
    assert kwargs["Key"] == {"CertId": "cert-1"}

    expected = (date.today() + timedelta(days=app.RENEWAL_VALIDITY_DAYS)).isoformat()
    assert result["expiryDate"] == expected
    assert result["status"] == "ISSUED"
    assert result["certId"] == "cert-1"
    assert result["mode"] == "RECORD_ONLY"


@patch("boto3.resource")
def test_update_item_never_receives_secret_or_private_key_fields(mock_resource):
    table = MagicMock()
    mock_resource.return_value.Table.return_value = table

    app.handler({"certId": "cert-1"}, None)

    kwargs = table.update_item.call_args.kwargs
    names = kwargs["ExpressionAttributeNames"]
    values = kwargs["ExpressionAttributeValues"]
    assert all(n.lstrip("#") in app.ALLOWED_UPDATE_FIELDS for n in names.values())
    assert not any("secret" in str(v).lower() for v in values.values())


@patch("boto3.resource")
def test_write_is_conditional_on_the_row_still_existing(mock_resource):
    """A renewal for a deleted CertId must fail loudly so the state machine
    catches it and writes a FAILURE audit event — not silently create a row
    holding nothing but an expiry date."""
    table = MagicMock()
    mock_resource.return_value.Table.return_value = table

    app.handler({"certId": "cert-1"}, None)

    assert table.update_item.call_args.kwargs["ConditionExpression"] == "attribute_exists(CertId)"


@patch("boto3.resource")
def test_a_dynamodb_failure_propagates(mock_resource):
    """No guard_api_handler here on purpose: this function is invoked by Step
    Functions, which needs the raise to trigger its Retry/Catch."""
    table = MagicMock()
    table.update_item.side_effect = RuntimeError("ConditionalCheckFailedException")
    mock_resource.return_value.Table.return_value = table

    try:
        app.handler({"certId": "cert-1"}, None)
    except RuntimeError:
        return
    raise AssertionError("handler swallowed the error instead of raising")
