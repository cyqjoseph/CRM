from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, call, patch

import botocore.exceptions
import pytest

from conftest import load_module

app = load_module("ec2_discovery_app", "functions/ec2_discovery/app.py")

INSTANCE_ID = "i-0123456789abcdef0"


def _clients(mock_client, ssm=None, cloudwatch=None):
    ssm = ssm or MagicMock()
    cloudwatch = cloudwatch or MagicMock()

    def side_effect(service_name, *args, **kwargs):
        return {"ssm": ssm, "cloudwatch": cloudwatch}[service_name]

    mock_client.side_effect = side_effect
    return ssm, cloudwatch


def _cert_block(
    path="/etc/ssl/certs/a.pem",
    serial="0a:1b:2c:3d:4e:5f:60:71",
    issuer="CN=DigiCert Global Root CA,O=DigiCert Inc,C=US",
    subject="CN=example.com,O=Example Inc,C=US",
    not_before="Jan  1 00:00:00 2020 GMT",
    not_after="Jan  1 00:00:00 2030 GMT",
    sans=None,
    parse_error=False,
):
    if parse_error:
        return f'===CERT_FILE_START:{path}===\n===CERT_PARSE_ERROR:{path}===\n===CERT_FILE_END:{path}===\n'

    lines = [
        "Certificate:",
        "    Data:",
        "        Serial Number:",
        f"            {serial}",
        f"        Issuer: {issuer}",
        "        Validity",
        f"            Not Before: {not_before}",
        f"            Not After : {not_after}",
        f"        Subject: {subject}",
    ]
    if sans:
        lines.append("        X509v3 Subject Alternative Name: ")
        lines.append("            " + ", ".join(f"DNS:{s}" for s in sans))
    body = "\n".join(lines) + "\n"
    return f"===CERT_FILE_START:{path}===\n{body}===CERT_FILE_END:{path}===\n"


def _success_invocation(stdout):
    return {"Status": "Success", "StandardOutputContent": stdout}


# ---------------------------------------------------------------------------
# Instance-id / dispatch error handling
# ---------------------------------------------------------------------------

@patch("boto3.client")
def test_missing_instance_id_parameter_is_handled_gracefully(mock_client):
    ssm, _ = _clients(mock_client)
    ssm.get_parameter.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ParameterNotFound", "Message": "not found"}}, "GetParameter"
    )

    result = app.handler({}, None)

    assert result == {"discovered": 0, "reason": "instance-id parameter not found"}
    ssm.send_command.assert_not_called()


@patch("boto3.client")
def test_send_command_failure_on_both_attempts_raises_for_eventbridge_retry(mock_client):
    ssm, _ = _clients(mock_client)
    ssm.get_parameter.return_value = {"Parameter": {"Value": INSTANCE_ID}}
    ssm.send_command.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "InvalidInstanceId", "Message": "not managed by SSM"}}, "SendCommand"
    )

    with pytest.raises(botocore.exceptions.ClientError):
        app.handler({}, None)

    assert ssm.send_command.call_count == 2


@patch.object(app, "_wait_for_command", return_value=None)
@patch("boto3.client")
def test_command_that_never_completes_is_retried_once_then_reported_gracefully(mock_client, mock_wait):
    ssm, _ = _clients(mock_client)
    ssm.get_parameter.return_value = {"Parameter": {"Value": INSTANCE_ID}}
    ssm.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}

    result = app.handler({}, None)

    assert ssm.send_command.call_count == 2
    assert result == {"instanceId": INSTANCE_ID, "totalCertsFound": 0, "reason": "command did not complete"}


def test_wait_for_command_polls_until_a_terminal_status():
    ssm = MagicMock()
    ssm.get_command_invocation.side_effect = [
        {"Status": "InProgress"},
        {"Status": "Success", "StandardOutputContent": "done"},
    ]
    with patch("ec2_discovery_app.time.sleep"):
        invocation = app._wait_for_command(ssm, INSTANCE_ID, "cmd-1", "req-1", budget_seconds=10)
    assert invocation["Status"] == "Success"


def test_wait_for_command_gives_up_after_the_time_budget():
    ssm = MagicMock()
    ssm.get_command_invocation.return_value = {"Status": "InProgress"}
    monotonic_values = iter([0, 1, 2, 3, 11])
    with patch("ec2_discovery_app.time.sleep"), \
         patch("ec2_discovery_app.time.monotonic", side_effect=lambda: next(monotonic_values)):
        invocation = app._wait_for_command(ssm, INSTANCE_ID, "cmd-1", "req-1", budget_seconds=10)
    assert invocation is None


# ---------------------------------------------------------------------------
# Discovery / parse / merge
# ---------------------------------------------------------------------------

@patch("boto3.resource")
@patch("boto3.client")
def test_new_certs_are_discovered_and_written_to_dynamodb(mock_client, mock_resource):
    ssm, _ = _clients(mock_client)
    ssm.get_parameter.return_value = {"Parameter": {"Value": INSTANCE_ID}}
    ssm.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
    stdout = _cert_block(
        path="/etc/ssl/certs/a.pem",
        issuer="CN=DigiCert Global Root CA,O=DigiCert Inc,C=US",
        subject="CN=example.com,O=Example Inc,C=US",
        not_after="Jan  1 00:00:00 2030 GMT",
    ) + _cert_block(
        path="/etc/ssl/certs/b.pem",
        serial="11:22:33:44:55:66:77:88",
        issuer="CN=Internal App CA,O=Acme Corp,C=US",
        subject="CN=internal.acme.local,O=Acme Corp,C=US",
        not_after="Jan  1 00:00:00 2020 GMT",
    )
    ssm.get_command_invocation.return_value = _success_invocation(stdout)

    table = MagicMock()
    table.query.return_value = {"Items": []}
    mock_resource.return_value.Table.return_value = table

    result = app.handler({}, None)

    assert result["totalCertsFound"] == 2
    assert result["newCerts"] == 2
    assert result["updatedCerts"] == 0
    assert table.put_item.call_count == 2

    written = {c.kwargs["Item"]["Domain"]: c.kwargs["Item"] for c in table.put_item.call_args_list}
    assert written["example.com"]["CertType"] == app.CERT_TYPE_SYSTEM_CA
    assert written["example.com"]["Status"] == "ISSUED"
    assert written["example.com"]["Source"] == "ec2-os-certs"
    assert written["example.com"]["OwnerId"] == "crm-resource-owners"
    assert written["example.com"]["InstanceId"] == INSTANCE_ID
    assert written["internal.acme.local"]["CertType"] == app.CERT_TYPE_SYSTEM_CA
    assert written["internal.acme.local"]["Status"] == "EXPIRED"


@patch("boto3.resource")
@patch("boto3.client")
def test_cert_id_is_a_deterministic_hash_of_serial_and_instance_id(mock_client, mock_resource):
    ssm, _ = _clients(mock_client)
    ssm.get_parameter.return_value = {"Parameter": {"Value": INSTANCE_ID}}
    ssm.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
    stdout = _cert_block(serial="0a:1b:2c:3d:4e:5f:60:71")
    ssm.get_command_invocation.return_value = _success_invocation(stdout)

    table = MagicMock()
    table.query.return_value = {"Items": []}
    mock_resource.return_value.Table.return_value = table

    app.handler({}, None)

    written_cert_id = table.put_item.call_args.kwargs["Item"]["CertId"]
    assert written_cert_id == app._compute_cert_id("0a1b2c3d4e5f6071", INSTANCE_ID)
    assert written_cert_id.startswith("ec2-")


@patch("boto3.resource")
@patch("boto3.client")
def test_existing_cert_is_updated_in_place_and_other_fields_are_left_alone(mock_client, mock_resource):
    ssm, _ = _clients(mock_client)
    ssm.get_parameter.return_value = {"Parameter": {"Value": INSTANCE_ID}}
    ssm.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
    stdout = _cert_block(serial="0a:1b:2c:3d:4e:5f:60:71", not_after="Jan  1 00:00:00 2030 GMT")
    ssm.get_command_invocation.return_value = _success_invocation(stdout)

    cert_id = app._compute_cert_id("0a1b2c3d4e5f6071", INSTANCE_ID)
    table = MagicMock()
    table.query.return_value = {
        "Items": [{
            "CertId": cert_id,
            "OwnerId": "crm-resource-owners",
            "Domain": "example.com",
            "Source": "ec2-os-certs",
            "ExpiryDate": "2019-01-01T00:00:00+00:00",
            "Status": "EXPIRED",
        }]
    }
    mock_resource.return_value.Table.return_value = table

    result = app.handler({}, None)

    assert result["newCerts"] == 0
    assert result["updatedCerts"] == 1
    table.put_item.assert_not_called()
    table.update_item.assert_called_once()
    kwargs = table.update_item.call_args.kwargs
    assert kwargs["Key"] == {"CertId": cert_id}
    assert kwargs["ExpressionAttributeValues"][":status"] == "ISSUED"
    assert "ExpiryDate = :expiry" in kwargs["UpdateExpression"]


@patch("boto3.resource")
@patch("boto3.client")
def test_cert_with_no_changes_is_still_updated_but_counted_as_unchanged(mock_client, mock_resource):
    ssm, _ = _clients(mock_client)
    ssm.get_parameter.return_value = {"Parameter": {"Value": INSTANCE_ID}}
    ssm.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
    stdout = _cert_block(serial="0a:1b:2c:3d:4e:5f:60:71", not_after="Jan  1 00:00:00 2030 GMT")
    ssm.get_command_invocation.return_value = _success_invocation(stdout)

    expiry_dt = app._parse_openssl_date("Jan  1 00:00:00 2030 GMT")
    cert_id = app._compute_cert_id("0a1b2c3d4e5f6071", INSTANCE_ID)
    table = MagicMock()
    table.query.return_value = {
        "Items": [{
            "CertId": cert_id,
            "OwnerId": "crm-resource-owners",
            "Source": "ec2-os-certs",
            "ExpiryDate": expiry_dt.isoformat(),
            "Status": "ISSUED",
        }]
    }
    mock_resource.return_value.Table.return_value = table

    result = app.handler({}, None)

    assert result["updatedCerts"] == 0
    assert result["unchangedCerts"] == 1
    table.update_item.assert_called_once()


@patch("boto3.resource")
@patch("boto3.client")
def test_query_ignores_rows_from_a_different_source(mock_client, mock_resource):
    ssm, _ = _clients(mock_client)
    ssm.get_parameter.return_value = {"Parameter": {"Value": INSTANCE_ID}}
    ssm.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
    stdout = _cert_block(serial="0a:1b:2c:3d:4e:5f:60:71")
    ssm.get_command_invocation.return_value = _success_invocation(stdout)

    cert_id = app._compute_cert_id("0a1b2c3d4e5f6071", INSTANCE_ID)
    table = MagicMock()
    table.query.return_value = {
        "Items": [{"CertId": cert_id, "OwnerId": "crm-resource-owners", "Source": "demo-seed", "Status": "ISSUED"}]
    }
    mock_resource.return_value.Table.return_value = table

    result = app.handler({}, None)

    assert result["newCerts"] == 1
    table.put_item.assert_called_once()


@patch("boto3.resource")
@patch("boto3.client")
def test_a_cert_that_fails_to_parse_is_skipped_but_others_still_discovered(mock_client, mock_resource):
    ssm, _ = _clients(mock_client)
    ssm.get_parameter.return_value = {"Parameter": {"Value": INSTANCE_ID}}
    ssm.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
    stdout = (
        _cert_block(path="/etc/ssl/certs/broken.pem", parse_error=True)
        + _cert_block(path="/etc/ssl/certs/good.pem")
    )
    ssm.get_command_invocation.return_value = _success_invocation(stdout)

    table = MagicMock()
    table.query.return_value = {"Items": []}
    mock_resource.return_value.Table.return_value = table

    result = app.handler({}, None)

    assert result["totalCertsFound"] == 1
    table.put_item.assert_called_once()


@patch("boto3.resource")
@patch("boto3.client")
def test_a_cert_block_missing_not_after_is_skipped(mock_client, mock_resource):
    ssm, _ = _clients(mock_client)
    ssm.get_parameter.return_value = {"Parameter": {"Value": INSTANCE_ID}}
    ssm.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
    stdout = _cert_block().replace("            Not After : Jan  1 00:00:00 2030 GMT\n", "")
    ssm.get_command_invocation.return_value = _success_invocation(stdout)

    table = MagicMock()
    table.query.return_value = {"Items": []}
    mock_resource.return_value.Table.return_value = table

    result = app.handler({}, None)

    assert result["totalCertsFound"] == 0
    table.put_item.assert_not_called()


@patch("ec2_discovery_app.time.sleep")
@patch("boto3.resource")
@patch("boto3.client")
def test_dynamodb_write_failure_retries_then_raises_and_publishes_error_metric(mock_client, mock_resource, mock_sleep):
    ssm, cloudwatch = _clients(mock_client)
    ssm.get_parameter.return_value = {"Parameter": {"Value": INSTANCE_ID}}
    ssm.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
    stdout = _cert_block()
    ssm.get_command_invocation.return_value = _success_invocation(stdout)

    table = MagicMock()
    table.query.return_value = {"Items": []}
    table.put_item.side_effect = Exception("throttled")
    mock_resource.return_value.Table.return_value = table

    with pytest.raises(Exception, match="throttled"):
        app.handler({}, None)

    assert table.put_item.call_count == app.DYNAMODB_MAX_RETRIES
    cloudwatch.put_metric_data.assert_called_once()
    metric_kwargs = cloudwatch.put_metric_data.call_args.kwargs
    assert metric_kwargs["Namespace"] == "app-d9fae51c-1929cc69/Ec2Discovery"


@patch("boto3.resource")
@patch("boto3.client")
def test_query_failure_is_treated_as_no_existing_certs_rather_than_fatal(mock_client, mock_resource):
    ssm, _ = _clients(mock_client)
    ssm.get_parameter.return_value = {"Parameter": {"Value": INSTANCE_ID}}
    ssm.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
    stdout = _cert_block()
    ssm.get_command_invocation.return_value = _success_invocation(stdout)

    table = MagicMock()
    table.query.side_effect = Exception("access denied")
    mock_resource.return_value.Table.return_value = table

    result = app.handler({}, None)

    assert result["newCerts"] == 1
    table.put_item.assert_called_once()


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def test_parse_serial_handles_the_colon_hex_block_form():
    assert app._parse_serial("Serial Number:\n    0a:1b:2c\n") == "0a1b2c"


def test_parse_serial_handles_the_inline_decimal_and_hex_form():
    text = "Serial Number: 1234567890 (0x499602d2)\n"
    assert app._parse_serial(text) == "499602d2"


def test_parse_openssl_date_handles_single_digit_days_with_the_double_space():
    parsed = app._parse_openssl_date("Jan  1 00:00:00 2030 GMT")
    assert parsed == datetime(2030, 1, 1, tzinfo=timezone.utc)


def test_parse_sans_extracts_only_dns_entries():
    text = "X509v3 Subject Alternative Name: \n    DNS:a.example.com, DNS:b.example.com\n"
    assert app._parse_sans(text) == ["a.example.com", "b.example.com"]


def test_parse_sans_returns_empty_list_when_absent():
    assert app._parse_sans("no sans here") == []


def test_extract_cn_reads_the_first_cn_attribute_in_rfc2253_order():
    assert app._extract_cn("CN=example.com,O=Example Inc,C=US") == "example.com"


def test_extract_cn_returns_none_for_a_dn_with_no_cn():
    assert app._extract_cn("O=Example Inc,C=US") is None


def test_compute_status_uses_the_same_vocabulary_as_expiry_alerting():
    """`Status` is ExpiryIndex's HASH key and expiry-evaluator-fn queries it with
    the literal "ISSUED". This function used to write "active"/"expiring-soon",
    so every certificate it discovered was silently excluded from alerting."""
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert app._compute_status(now - timedelta(days=1), now) == "EXPIRED"
    assert app._compute_status(now + timedelta(days=10), now) == "ISSUED"
    assert app._compute_status(now + timedelta(days=60), now) == "ISSUED"


def test_classify_cert_type_uses_the_directory_when_it_knows_it():
    """An internal CA whose name contains a public brand must not file an
    application certificate as a system root."""
    app_path = f"{app.APP_CERT_DIR}/payments.pem"
    assert app._classify_cert_type("CN=Amazon Internal CA", app_path) == app.CERT_TYPE_APP
    system_path = f"{app.SYSTEM_CERT_DIR}/DigiCert.pem"
    assert app._classify_cert_type("CN=Internal App CA,O=Acme Corp,C=US", system_path) == app.CERT_TYPE_SYSTEM_CA


def test_classify_cert_type_falls_back_to_the_issuer_when_the_path_is_unknown():
    assert app._classify_cert_type("CN=DigiCert Global Root CA,O=DigiCert Inc,C=US") == app.CERT_TYPE_SYSTEM_CA
    assert app._classify_cert_type("CN=Internal App CA,O=Acme Corp,C=US") == app.CERT_TYPE_APP
    assert app._classify_cert_type(None) == app.CERT_TYPE_APP


def test_compute_cert_id_is_stable_for_the_same_inputs():
    assert app._compute_cert_id("abc123", INSTANCE_ID) == app._compute_cert_id("abc123", INSTANCE_ID)
    assert app._compute_cert_id("abc123", INSTANCE_ID) != app._compute_cert_id("abc124", INSTANCE_ID)


def test_build_cert_item_prefers_subject_cn_then_san_then_issuer_cn():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    with_subject = _cert_block(subject="CN=subject.example.com,O=Acme,C=US", sans=["san.example.com"])
    block = with_subject.split("===\n", 1)[1].split("===CERT_FILE_END", 1)[0]
    item = app._build_cert_item(block, INSTANCE_ID, now)
    assert item["Domain"] == "subject.example.com"

    no_subject_cn = _cert_block(subject="O=Acme,C=US", sans=["san.example.com"])
    block2 = no_subject_cn.split("===\n", 1)[1].split("===CERT_FILE_END", 1)[0]
    item2 = app._build_cert_item(block2, INSTANCE_ID, now)
    assert item2["Domain"] == "san.example.com"


# ---------------------------------------------------------------------------
# Application certificates vs the OS trust store
# ---------------------------------------------------------------------------
#
# The instance's UserData builds an internal CA at first boot, generates a key
# and a CSR per hostname, signs each with that CA, and installs the leaf into
# APP_CERT_DIR. Those are the rows the dashboard exists to show; /etc/ssl/certs
# is the ~140-entry OS trust store and must not crowd them out.


def test_the_scan_command_enumerates_the_application_directory_first():
    command = app.build_scan_command()
    assert app.APP_CERT_DIR in command
    assert app.SYSTEM_CERT_DIR in command
    assert command.index(app.APP_CERT_DIR) < command.index(app.SYSTEM_CERT_DIR), (
        "the application certificates must be listed before the capped trust store, "
        "or the cap can consume the whole listing"
    )


def test_the_scan_command_caps_the_trust_store_but_never_the_application_certs():
    command = app.build_scan_command(system_limit=7)
    assert "head -7" in command
    app_clause = command[command.index(app.APP_CERT_DIR):command.index(app.SYSTEM_CERT_DIR)]
    assert "head" not in app_clause


def test_the_scan_command_can_skip_the_trust_store_entirely():
    command = app.build_scan_command(system_limit=0)
    assert app.APP_CERT_DIR in command
    assert app.SYSTEM_CERT_DIR not in command


def test_the_scan_command_follows_symlinks():
    """Ubuntu populates /etc/ssl/certs with per-certificate symlinks; a bare
    `find -type f` there matches almost nothing."""
    assert "find -L" in app.build_scan_command()


@patch("boto3.resource")
@patch("boto3.client")
def test_an_application_certificate_is_filed_and_reported_as_one(mock_client, mock_resource):
    ssm, _ = _clients(mock_client)
    ssm.get_parameter.return_value = {"Parameter": {"Value": INSTANCE_ID}}
    ssm.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
    stdout = _cert_block(
        path=f"{app.APP_CERT_DIR}/payments.pem",
        issuer="CN=app-d9fae51c-1929cc69 Internal CA,O=CRM,C=SG",
        subject="CN=payments.internal.example.com,O=CRM,C=SG",
        not_after="Jan  1 00:00:00 2030 GMT",
    ) + _cert_block(
        path=f"{app.SYSTEM_CERT_DIR}/DigiCert_Global_Root_CA.pem",
        serial="11:22:33:44:55:66:77:88",
        issuer="CN=DigiCert Global Root CA,O=DigiCert Inc,C=US",
        subject="CN=DigiCert Global Root CA,O=DigiCert Inc,C=US",
        not_after="Jan  1 00:00:00 2031 GMT",
    )
    ssm.get_command_invocation.return_value = _success_invocation(stdout)

    table = MagicMock()
    table.query.return_value = {"Items": []}
    mock_resource.return_value.Table.return_value = table

    result = app.handler({}, None)

    assert result["totalCertsFound"] == 2
    assert result["appCerts"] == 1, "the app/system split is what tells us the CA step ran"

    written = {c.kwargs["Item"]["Domain"]: c.kwargs["Item"] for c in table.put_item.call_args_list}
    leaf = written["payments.internal.example.com"]
    assert leaf["CertType"] == app.CERT_TYPE_APP
    assert leaf["CertPath"] == f"{app.APP_CERT_DIR}/payments.pem"
    assert leaf["Issuer"].startswith("CN=app-d9fae51c-1929cc69 Internal CA")
    assert written["DigiCert Global Root CA"]["CertType"] == app.CERT_TYPE_SYSTEM_CA


@patch("boto3.resource")
@patch("boto3.client")
def test_an_empty_application_directory_is_reported_not_silently_passed(mock_client, mock_resource):
    """The trust store alone still yields rows, so a failed certificate-issuing
    step looks exactly like a successful scan unless it is called out."""
    ssm, _ = _clients(mock_client)
    ssm.get_parameter.return_value = {"Parameter": {"Value": INSTANCE_ID}}
    ssm.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
    ssm.get_command_invocation.return_value = _success_invocation(
        _cert_block(path=f"{app.SYSTEM_CERT_DIR}/x.pem")
    )

    table = MagicMock()
    table.query.return_value = {"Items": []}
    mock_resource.return_value.Table.return_value = table

    with patch.object(app, "structured_log") as log:
        result = app.handler({}, None)

    assert result["appCerts"] == 0
    assert any(c.args[1] == "EC2_DISCOVERY_NO_APP_CERTS" for c in log.call_args_list)


# ---------------------------------------------------------------------------
# Pruning rows left behind by a replaced instance
# ---------------------------------------------------------------------------


@patch("boto3.resource")
@patch("boto3.client")
def test_rows_from_a_replaced_instance_are_deleted(mock_client, mock_resource):
    """CertId hashes in the instance id, and any UserData change replaces the
    instance — so without this every deploy leaves a full set of orphans that
    never update again and drift into EXPIRED."""
    ssm, _ = _clients(mock_client)
    ssm.get_parameter.return_value = {"Parameter": {"Value": INSTANCE_ID}}
    ssm.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
    ssm.get_command_invocation.return_value = _success_invocation(_cert_block())

    table = MagicMock()
    table.query.return_value = {
        "Items": [{
            "CertId": "ec2-orphan",
            "OwnerId": "crm-resource-owners",
            "Source": app.SOURCE_NAME,
            "InstanceId": "i-000000000deadbeef",
            "Status": "ISSUED",
        }]
    }
    mock_resource.return_value.Table.return_value = table

    result = app.handler({}, None)

    assert result["prunedCerts"] == 1
    table.delete_item.assert_called_once_with(Key={"CertId": "ec2-orphan"})


@patch("boto3.resource")
@patch("boto3.client")
def test_rows_from_the_current_instance_are_never_pruned(mock_client, mock_resource):
    ssm, _ = _clients(mock_client)
    ssm.get_parameter.return_value = {"Parameter": {"Value": INSTANCE_ID}}
    ssm.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
    ssm.get_command_invocation.return_value = _success_invocation(_cert_block())

    cert_id = app._compute_cert_id("0a1b2c3d4e5f6071", INSTANCE_ID)
    table = MagicMock()
    table.query.return_value = {
        "Items": [{
            "CertId": cert_id,
            "OwnerId": "crm-resource-owners",
            "Source": app.SOURCE_NAME,
            "InstanceId": INSTANCE_ID,
            "ExpiryDate": "2030-01-01T00:00:00+00:00",
            "Status": "ISSUED",
        }]
    }
    mock_resource.return_value.Table.return_value = table

    result = app.handler({}, None)

    assert result["prunedCerts"] == 0
    table.delete_item.assert_not_called()


@patch("boto3.resource")
@patch("boto3.client")
def test_a_row_with_no_instance_id_is_left_alone_rather_than_guessed_about(mock_client, mock_resource):
    ssm, _ = _clients(mock_client)
    ssm.get_parameter.return_value = {"Parameter": {"Value": INSTANCE_ID}}
    ssm.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
    ssm.get_command_invocation.return_value = _success_invocation(_cert_block())

    table = MagicMock()
    table.query.return_value = {
        "Items": [{"CertId": "ec2-legacy", "OwnerId": "crm-resource-owners",
                   "Source": app.SOURCE_NAME, "Status": "ISSUED"}]
    }
    mock_resource.return_value.Table.return_value = table

    result = app.handler({}, None)

    assert result["prunedCerts"] == 0
    table.delete_item.assert_not_called()


@patch("boto3.resource")
@patch("boto3.client")
def test_pruning_never_touches_a_row_from_another_source(mock_client, mock_resource):
    """_existing_certs_by_id filters on Source, so a demo-seed or IAM-discovered
    row can never reach the pruner — this pins that down."""
    ssm, _ = _clients(mock_client)
    ssm.get_parameter.return_value = {"Parameter": {"Value": INSTANCE_ID}}
    ssm.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
    ssm.get_command_invocation.return_value = _success_invocation(_cert_block())

    table = MagicMock()
    table.query.return_value = {
        "Items": [{"CertId": "demo-cert-0001", "OwnerId": "crm-resource-owners",
                   "Source": "demo-seed", "InstanceId": "i-000000000deadbeef"}]
    }
    mock_resource.return_value.Table.return_value = table

    result = app.handler({}, None)

    assert result["prunedCerts"] == 0
    table.delete_item.assert_not_called()


@patch("boto3.resource")
@patch("boto3.client")
def test_a_failed_prune_is_logged_and_does_not_abort_the_cycle(mock_client, mock_resource):
    ssm, _ = _clients(mock_client)
    ssm.get_parameter.return_value = {"Parameter": {"Value": INSTANCE_ID}}
    ssm.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
    ssm.get_command_invocation.return_value = _success_invocation(_cert_block())

    table = MagicMock()
    table.query.return_value = {
        "Items": [{"CertId": "ec2-orphan", "OwnerId": "crm-resource-owners",
                   "Source": app.SOURCE_NAME, "InstanceId": "i-000000000deadbeef"}]
    }
    table.delete_item.side_effect = Exception("ConditionalCheckFailed")
    mock_resource.return_value.Table.return_value = table

    result = app.handler({}, None)

    assert result["prunedCerts"] == 0
    assert result["newCerts"] == 1, "a failed prune must not stop the discovery write"


@patch("boto3.resource")
@patch("boto3.client")
def test_an_in_place_update_corrects_the_owner_type_and_status_of_an_older_row(mock_client, mock_resource):
    """Rows written under the old "active"/"expiring-soon" vocabulary, or before
    CertType/InstanceId existed, must be corrected on the next cycle rather than
    staying wrong until someone deletes them by hand."""
    ssm, _ = _clients(mock_client)
    ssm.get_parameter.return_value = {"Parameter": {"Value": INSTANCE_ID}}
    ssm.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
    ssm.get_command_invocation.return_value = _success_invocation(
        _cert_block(path=f"{app.APP_CERT_DIR}/payments.pem", not_after="Jan  1 00:00:00 2030 GMT")
    )

    cert_id = app._compute_cert_id("0a1b2c3d4e5f6071", INSTANCE_ID)
    table = MagicMock()
    table.query.return_value = {
        "Items": [{
            "CertId": cert_id, "OwnerId": "some-cognito-sub", "Source": app.SOURCE_NAME,
            "ExpiryDate": "2030-01-01T00:00:00+00:00", "Status": "active",
        }]
    }
    mock_resource.return_value.Table.return_value = table

    app.handler({}, None)

    values = table.update_item.call_args.kwargs["ExpressionAttributeValues"]
    assert values[":status"] == "ISSUED"
    assert values[":ownerId"] == "crm-resource-owners"
    assert values[":certType"] == app.CERT_TYPE_APP
    assert values[":instanceId"] == INSTANCE_ID
