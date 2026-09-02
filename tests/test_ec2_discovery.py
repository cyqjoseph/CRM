from unittest.mock import MagicMock, patch

import botocore.exceptions
import pytest

from conftest import load_module

app = load_module("ec2_discovery_app", "functions/ec2_discovery/app.py")


@patch("boto3.client")
def test_dispatches_run_command_against_the_discovered_instance(mock_client):
    ssm = MagicMock()
    ssm.get_parameter.return_value = {"Parameter": {"Value": "i-0123456789abcdef0"}}
    ssm.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
    mock_client.return_value = ssm

    result = app.handler({}, None)

    assert result == {
        "dispatched": True,
        "instanceId": "i-0123456789abcdef0",
        "commandId": "cmd-1",
    }
    ssm.get_parameter.assert_called_once_with(Name=app.INSTANCE_ID_PARAM_NAME)
    args, kwargs = ssm.send_command.call_args
    assert kwargs["InstanceIds"] == ["i-0123456789abcdef0"]
    assert kwargs["DocumentName"] == "AWS-RunShellScript"
    assert "commands" in kwargs["Parameters"]


@patch("boto3.client")
def test_missing_instance_id_parameter_is_reported_without_raising(mock_client):
    ssm = MagicMock()
    ssm.get_parameter.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ParameterNotFound", "Message": "not found"}}, "GetParameter"
    )
    mock_client.return_value = ssm

    result = app.handler({}, None)

    assert result["dispatched"] is False
    ssm.send_command.assert_not_called()


@patch("boto3.client")
def test_send_command_failure_is_raised_so_eventbridge_retries(mock_client):
    ssm = MagicMock()
    ssm.get_parameter.return_value = {"Parameter": {"Value": "i-0123456789abcdef0"}}
    ssm.send_command.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "InvalidInstanceId", "Message": "not managed by SSM"}}, "SendCommand"
    )
    mock_client.return_value = ssm

    with pytest.raises(botocore.exceptions.ClientError):
        app.handler({}, None)
