"""api-executions-fn: GET /executions/{executionId}.

The GET /audit tests that used to live here are gone with the route. It required
the caller to already know a resource's exact id, so every search a person
actually typed — a prefix like "demo-cert" — matched nothing and was refused as an
unresolvable cross-owner lookup. The audit trail itself still gets written; only
the search endpoint is withdrawn.
"""
import json
from unittest.mock import MagicMock, patch

from conftest import load_module

app = load_module("api_executions_app", "functions/api_executions/app.py")


def _execution_event(execution_id, claims):
    return {
        "resource": "/executions/{executionId}",
        "pathParameters": {"executionId": execution_id},
        "queryStringParameters": None,
        "requestContext": {"authorizer": {"claims": claims}},
    }


@patch("boto3.resource")
@patch("boto3.client")
def test_get_execution_returns_status_and_output(mock_client, mock_resource):
    sfn = MagicMock()
    sfn.describe_execution.return_value = {"status": "SUCCEEDED", "output": '{"ok": true}'}
    sfn.get_execution_history.return_value = {"events": []}
    mock_client.return_value = sfn

    response = app.handler(
        _execution_event("arn:aws:states:renewal:exec-1", {"sub": "owner-1"}), None
    )

    assert response["statusCode"] == 200
    body = json.loads(response["body"])
    assert body["status"] == "SUCCEEDED"
    sfn.get_execution_history.assert_called_once()


@patch("boto3.resource")
@patch("boto3.client")
def test_get_execution_returns_500_with_details_on_failure(mock_client, mock_resource):
    sfn = MagicMock()
    sfn.describe_execution.side_effect = Exception("AccessDeniedException: not authorized")
    mock_client.return_value = sfn

    response = app.handler(
        _execution_event("arn:aws:states:renewal:exec-1", {"sub": "owner-1"}), None
    )

    assert response["statusCode"] == 500
    body = json.loads(response["body"])
    assert body["error"] == "DescribeExecution call failed"
    assert "not authorized" in body["details"]


# --- Percent-encoded execution ARNs ------------------------------------------
# An execution ARN is full of colons, so the browser must percent-encode it into
# the path. API Gateway REST APIs then hand it to Lambda STILL ENCODED, and
# DescribeExecution rejects it with
#   InvalidArn: Invalid ARN prefix: arn%3Aaws%3Astates%3A...
# which reads like the caller sent a bad ARN rather than an un-decoded one. This
# broke every renew/rotate status poll in the browser while working fine from
# curl with an unencoded ARN.

ENCODED_ARN = (
    "arn%3Aaws%3Astates%3Aap-southeast-1%3A544635841962%3Aexecution%3A"
    "app-d9fae51c-1929cc69-renewal-sfn%3Ad29130d9-fefd-4ee2-9387-d07c33b9d02a"
)
DECODED_ARN = (
    "arn:aws:states:ap-southeast-1:544635841962:execution:"
    "app-d9fae51c-1929cc69-renewal-sfn:d29130d9-fefd-4ee2-9387-d07c33b9d02a"
)


@patch("boto3.resource")
@patch("boto3.client")
def test_a_percent_encoded_execution_arn_is_decoded_before_the_aws_call(mock_client, mock_resource):
    sfn = MagicMock()
    sfn.describe_execution.return_value = {"status": "SUCCEEDED", "output": "{}"}
    sfn.get_execution_history.return_value = {"events": []}
    mock_client.return_value = sfn

    response = app.handler(_execution_event(ENCODED_ARN, {"sub": "owner-1"}), None)

    assert response["statusCode"] == 200
    sfn.describe_execution.assert_called_once_with(executionArn=DECODED_ARN)


@patch("boto3.resource")
@patch("boto3.client")
def test_an_already_decoded_arn_is_passed_through_unchanged(mock_client, mock_resource):
    """Decoding must be idempotent — a well-formed ARN contains no '%', so it
    must survive unquote() untouched whichever way API Gateway behaves."""
    sfn = MagicMock()
    sfn.describe_execution.return_value = {"status": "RUNNING"}
    mock_client.return_value = sfn

    response = app.handler(_execution_event(DECODED_ARN, {"sub": "owner-1"}), None)

    assert response["statusCode"] == 200
    sfn.describe_execution.assert_called_once_with(executionArn=DECODED_ARN)


@patch("boto3.resource")
@patch("boto3.client")
def test_a_malformed_arn_is_a_400_not_a_500(mock_client, mock_resource):
    """Bad caller input is not a server error, and botocore's ParamValidationError
    is far less legible than saying what was expected."""
    sfn = MagicMock()
    mock_client.return_value = sfn

    response = app.handler(_execution_event("not-an-arn", {"sub": "owner-1"}), None)

    assert response["statusCode"] == 400
    body = json.loads(response["body"])
    assert "execution ARN" in body["error"]
    sfn.describe_execution.assert_not_called()


@patch("boto3.resource")
@patch("boto3.client")
def test_a_missing_execution_id_is_a_400_not_a_500(mock_client, mock_resource):
    sfn = MagicMock()
    mock_client.return_value = sfn

    event = _execution_event("ignored", {"sub": "owner-1"})
    event["pathParameters"] = {}

    response = app.handler(event, None)

    assert response["statusCode"] == 400
    sfn.describe_execution.assert_not_called()

