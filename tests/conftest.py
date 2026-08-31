"""Test bootstrap: sets Lambda env vars and loads each function's app.py as a
uniquely-named module (they're all called app.py, so a plain `import app`
would collide across test files)."""
import importlib.util
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "layers" / "common" / "python"))

os.environ.setdefault("CERT_TABLE_NAME", "test-cert-inventory")
os.environ.setdefault("IAM_TABLE_NAME", "test-iam-accounts")
os.environ.setdefault("AUDIT_TABLE_NAME", "test-audit-hot")
os.environ.setdefault("ARCHIVE_BUCKET_NAME", "test-audit-archive")
os.environ.setdefault("JIRA_QUEUE_URL", "https://sqs.ap-southeast-1.amazonaws.com/123456789012/test-jira-queue")
os.environ.setdefault("SNS_TOPIC_LOW", "arn:aws:sns:ap-southeast-1:123456789012:test-alerts-low")
os.environ.setdefault("SNS_TOPIC_MEDIUM", "arn:aws:sns:ap-southeast-1:123456789012:test-alerts-medium")
os.environ.setdefault("SNS_TOPIC_HIGH", "arn:aws:sns:ap-southeast-1:123456789012:test-alerts-high")
os.environ.setdefault("JIRA_TOKEN_SECRET_ARN", "arn:aws:secretsmanager:ap-southeast-1:123456789012:secret:test-jira-token")
os.environ.setdefault("JIRA_BASE_URL", "https://example.atlassian.net")
os.environ.setdefault("RENEWAL_STATE_MACHINE_ARN", "arn:aws:states:ap-southeast-1:123456789012:stateMachine:test-renewal-sfn")
os.environ.setdefault("ROTATION_STATE_MACHINE_ARN", "arn:aws:states:ap-southeast-1:123456789012:stateMachine:test-rotation-sfn")


def load_module(name, relative_path):
    """Import functions/<dir>/app.py under a unique module name."""
    path = ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module
