"""Runs cfn-lint over template.yaml as part of the suite.

Every mistake in an IaC template surfaces as a CREATE_FAILED partway through a
deploy, and CloudFormation reports the rest of that creation wave only as
"Resource creation cancelled" — so one bad property costs a full deploy cycle and
usually names the wrong resource. cfn-lint validates against AWS's own resource
schemas locally, which turns most of those into a test failure instead.

cfn-lint does NOT cover every service enum (it accepts an invalid Cognito
MfaConfiguration, for instance), so this complements rather than replaces the
explicit checks in test_template.py.
"""
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CFN_LINT = shutil.which("cfn-lint")


@pytest.mark.skipif(CFN_LINT is None, reason="cfn-lint not installed")
def test_cfn_lint_reports_no_errors():
    result = subprocess.run(
        [CFN_LINT, "template.yaml"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    output = (result.stdout + result.stderr).strip()
    assert not output, f"cfn-lint reported findings in template.yaml:\n{output}"
