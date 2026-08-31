from unittest.mock import MagicMock, patch

from conftest import load_module

app = load_module("discovery_ad_trigger_app", "functions/discovery_ad_trigger/app.py")


@patch("boto3.client")
def test_run_task_called_with_configured_task_definition(mock_client):
    ecs = MagicMock()
    mock_client.return_value = ecs

    ecs.run_task.return_value = {"failures": [], "tasks": [{"taskArn": "arn:aws:ecs:task/abc"}]}
    ecs.get_waiter.return_value = MagicMock()
    ecs.describe_tasks.return_value = {
        "tasks": [{"containers": [{"name": "ad-agent", "exitCode": 0}]}]
    }

    result = app.handler({}, None)

    ecs.run_task.assert_called_once()
    _, kwargs = ecs.run_task.call_args
    assert kwargs["taskDefinition"] == "app-d9fae51c-1929cc69-ad-task-def"
    assert kwargs["launchType"] == "FARGATE"
    assert result["exitCode"] == 0


@patch("boto3.client")
def test_raises_when_ad_agent_task_exits_non_zero(mock_client):
    ecs = MagicMock()
    mock_client.return_value = ecs

    ecs.run_task.return_value = {"failures": [], "tasks": [{"taskArn": "arn:aws:ecs:task/abc"}]}
    ecs.get_waiter.return_value = MagicMock()
    ecs.describe_tasks.return_value = {
        "tasks": [{"containers": [{"name": "ad-agent", "exitCode": 1}]}]
    }

    try:
        app.handler({}, None)
        assert False, "expected RuntimeError"
    except RuntimeError:
        pass
