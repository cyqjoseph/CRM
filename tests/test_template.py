"""Structural checks against template.yaml that don't require a live AWS account.

Complements `sam validate` (schema-level) with the specific per-task "Verify"
criteria from spec/tasks.md that are checkable by inspecting the template
itself: routes present (task 6), X-Ray tracing enabled (task 24), and IAM
policies free of wildcard Resources outside AWS's documented, unavoidable
exceptions (tasks 25/27/28/29/31/32).
"""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


class _CfnLoader(yaml.SafeLoader):
    pass


def _intrinsic(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return {"Fn::" + tag_suffix: loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {"Fn::" + tag_suffix: loader.construct_sequence(node)}
    return {"Fn::" + tag_suffix: loader.construct_mapping(node)}


_CfnLoader.add_multi_constructor("!", _intrinsic)


def _load_template():
    with open(ROOT / "template.yaml") as f:
        return yaml.load(f, Loader=_CfnLoader)


TEMPLATE = _load_template()
RESOURCES = TEMPLATE["Resources"]

REQUIRED_ROUTES = {
    ("/certs", "get"),
    ("/certs/{certId}", "get"),
    ("/certs/{certId}/renew", "post"),
    ("/iam/accounts", "get"),
    ("/iam/accounts/{accountId}", "get"),
    ("/iam/accounts/{accountId}/rotate", "post"),
    ("/executions/{executionId}", "get"),
    ("/audit", "get"),
    ("/password-resets", "post"),
    ("/password-resets", "get"),
    ("/password-resets/{requestId}/approve", "post"),
    ("/password-resets/{requestId}/reject", "post"),
    ("/health", "get"),
}

# Actions that AWS's IAM Service Authorization Reference documents as NOT
# supporting resource-level permissions at all — a wildcard Resource is the
# only valid value for these, not a scoping gap. The CloudWatch Logs and X-Ray
# actions are here for a different reason: each is called before the resource it
# would be scoped to exists (a log group is created by the function's own first
# invocation, a trace segment by the call that emits it), so even a
# correctly-scoped ARN would deny that first call.
MANDATORY_WILDCARD_ACTIONS = {
    "secretsmanager:ListSecrets",
    "iam:ListServerCertificates",
    "iam:ListUsers",
    "iam:ListAccessKeys",
    "logs:CreateLogGroup",
    "logs:CreateLogStream",
    "logs:PutLogEvents",
    "logs:DescribeLogGroups",
    "logs:DescribeLogStreams",
    # X-Ray's write/sampling actions accept no resource ARN at all — the trace
    # does not exist yet when PutTraceSegments is called, and the sampling rules
    # are account-level. Needed on each state machine role because they supply
    # their own Role, so SAM injects no X-Ray grant of its own.
    "xray:PutTraceSegments",
    "xray:PutTelemetryRecords",
    "xray:GetSamplingRules",
    "xray:GetSamplingTargets",
    # CloudWatch's metric-write action accepts no resource ARN — metrics are
    # identified by namespace/name in the request body, not an ARN. Granted to
    # ec2-discovery-fn to publish a fatal-error count.
    "cloudwatch:PutMetricData",
}


def test_all_required_api_routes_are_defined():
    found = set()
    for resource in RESOURCES.values():
        if resource.get("Type") != "AWS::Serverless::Function":
            continue
        for event in (resource.get("Properties", {}).get("Events") or {}).values():
            if event.get("Type") == "Api":
                props = event["Properties"]
                found.add((props["Path"], props["Method"]))

    missing = REQUIRED_ROUTES - found
    assert not missing, f"routes missing from template.yaml: {missing}"


def test_tracing_active_for_all_functions():
    assert TEMPLATE["Globals"]["Function"]["Tracing"] == "Active"
    for resource in RESOURCES.values():
        if resource.get("Type") != "AWS::Serverless::Function":
            continue
        # A function-level override, if present, must not turn tracing off.
        override = resource.get("Properties", {}).get("Tracing")
        assert override in (None, "Active")


def test_api_and_state_machines_have_tracing_enabled():
    assert RESOURCES["CrmApi"]["Properties"]["TracingEnabled"] is True
    for name in ("DiscoverySfn", "RenewalSfn", "RotationSfn", "PasswordResetSfn"):
        assert RESOURCES[name]["Properties"]["Tracing"]["Enabled"] is True


def _iter_statements():
    for logical_id, resource in RESOURCES.items():
        rtype = resource.get("Type")
        if rtype == "AWS::Serverless::Function":
            for policy in resource.get("Properties", {}).get("Policies", []) or []:
                if isinstance(policy, dict) and "Statement" in policy:
                    for statement in policy["Statement"]:
                        yield logical_id, statement
        elif rtype == "AWS::IAM::Role":
            for policy in resource.get("Properties", {}).get("Policies", []) or []:
                for statement in policy.get("PolicyDocument", {}).get("Statement", []):
                    yield logical_id, statement


def test_no_wildcard_resource_outside_documented_exceptions():
    for logical_id, statement in _iter_statements():
        resource = statement.get("Resource")
        if resource != "*":
            continue
        actions = statement["Action"]
        actions = [actions] if isinstance(actions, str) else actions
        for action in actions:
            assert action in MANDATORY_WILDCARD_ACTIONS, (
                f"{logical_id} grants wildcard Resource for {action}, which does "
                "support resource-level scoping — narrow it"
            )


def test_pass_role_statements_scope_to_named_role_arns_not_wildcard():
    """No iam:PassRole grant should ever target a wildcard resource.

    The current architecture (ECS/Fargate removed) has no legitimate
    iam:PassRole use case at all, so zero statements is expected and fine —
    this only guards against one being reintroduced with Resource: "*".
    """
    for logical_id, statement in _iter_statements():
        actions = statement["Action"]
        actions = [actions] if isinstance(actions, str) else actions
        if "iam:PassRole" not in actions:
            continue
        resource = statement["Resource"]
        resources = [resource] if isinstance(resource, (str, dict)) else resource
        assert resources != "*"
        for r in resources:
            assert r != "*", f"{logical_id} grants iam:PassRole on a wildcard resource"


def test_resource_names_use_the_mandated_prefix():
    prefix = "app-d9fae51c-1929cc69-"
    nameable_props = (
        "FunctionName",
        "TableName",
        "BucketName",
        "TopicName",
        "QueueName",
        "RoleName",
        "ClusterName",
        "Family",
        "GroupName",
        "Name",
        "AlarmName",
        "DashboardName",
        "LogGroupName",
    )
    # SSM parameters live under a path, not a name prefix (see CLAUDE.md's
    # Configuration and secrets section); group names within a user pool
    # aren't a top-level AWS resource name and aren't required to carry it.
    exempt_types = {"AWS::SSM::Parameter", "AWS::Cognito::UserPoolGroup"}

    for logical_id, resource in RESOURCES.items():
        if resource.get("Type") in exempt_types:
            continue
        props = resource.get("Properties", {}) or {}
        for prop in nameable_props:
            value = props.get(prop)
            if isinstance(value, str) and value:
                assert value.startswith(prefix), (
                    f"{logical_id}.{prop} = {value!r} does not start with {prefix!r}"
                )


def test_mfa_configuration_is_the_string_off_not_a_boolean():
    """Cognito's MfaConfiguration enum is [OPTIONAL, OFF, ON] — all strings.

    Bare `OFF` is a YAML 1.1 boolean alias, so `MfaConfiguration: OFF` parses as
    False and CloudFormation sends the string 'false', which fails validation
    with "Value 'false' at 'mfaConfiguration' failed to satisfy constraint".
    It must be quoted.
    """
    mfa = RESOURCES["UserPool"]["Properties"]["MfaConfiguration"]
    assert not isinstance(mfa, bool), (
        "MfaConfiguration parsed as a boolean — quote it as \"OFF\" so it stays "
        "the string Cognito's enum requires"
    )
    assert mfa == "OFF"


# YAML 1.1 resolves all of these bare words to booleans. CloudFormation applies
# that resolution too, so any of them left unquoted silently becomes true/false
# and is sent to the service as the string 'true'/'false' — which fails only at
# CREATE time, inside the deploy. Lowercase true/false are unambiguous and fine.
YAML11_BOOLEAN_ALIASES = {
    "y", "yes", "n", "no", "on", "off",
    "Y", "Yes", "YES", "N", "No", "NO", "On", "ON", "Off", "OFF",
    "True", "TRUE", "False", "FALSE",
}


def test_no_unquoted_yaml_boolean_aliases_in_the_template():
    offenders = []
    for lineno, line in enumerate(
        (ROOT / "template.yaml").read_text().splitlines(), start=1
    ):
        stripped = line.strip()
        if stripped.startswith("#") or ":" not in stripped:
            continue
        value = stripped.split(":", 1)[1].strip()
        if value.split("#", 1)[0].strip() in YAML11_BOOLEAN_ALIASES:
            offenders.append(f"template.yaml:{lineno}: {stripped}")

    assert not offenders, (
        "these values are YAML 1.1 boolean aliases and will be coerced to "
        "true/false — quote them if the service expects a string:\n"
        + "\n".join(offenders)
    )


# CLAUDE.md's given public subnet ids for the account's existing default VPC —
# the only subnets a new resource may be placed in.
ALLOWED_PUBLIC_SUBNET_IDS = {
    "subnet-0f43b5569d97d4bda",
    "subnet-0f0834e47e6db3a6d",
    "subnet-07a510b42806744f0",
}


def test_cert_scanner_security_group_has_no_inbound_rules():
    """SSH access to the cert-scanner instance goes through SSM Session Manager
    (AmazonSSMManagedInstanceCore on Ec2CertScannerRole), not an open port 22 —
    so this security group must carry no SecurityGroupIngress at all."""
    sg = RESOURCES["Ec2CertScannerSecurityGroup"]["Properties"]
    assert "SecurityGroupIngress" not in sg
    assert sg["VpcId"] == "vpc-01d3b02b0f1c07aa0"


def test_cert_scanner_instance_is_t3_micro_in_an_allowed_public_subnet():
    instance = RESOURCES["Ec2CertScannerInstance"]["Properties"]
    assert instance["InstanceType"] == "t3.micro"
    assert instance["SubnetId"] in ALLOWED_PUBLIC_SUBNET_IDS


def test_cert_scanner_root_volume_is_20gb_gp3_encrypted():
    instance = RESOURCES["Ec2CertScannerInstance"]["Properties"]
    ebs = instance["BlockDeviceMappings"][0]["Ebs"]
    assert ebs["VolumeSize"] == 20
    assert ebs["VolumeType"] == "gp3"
    assert ebs["Encrypted"] is True


def test_cert_scanner_role_has_ssm_managed_instance_core_and_boundary():
    role = RESOURCES["Ec2CertScannerRole"]["Properties"]
    assert "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore" in role["ManagedPolicyArns"]
    assert role["PermissionsBoundary"] == (
        "arn:aws:iam::544635841962:policy/brd-architect-deploy-boundary"
    )


def test_cert_scanner_ssm_parameters_live_under_the_mandated_path():
    for logical_id in ("Ec2CertScannerInstanceIdParam", "Ec2CertScannerPrivateIpParam"):
        name = RESOURCES[logical_id]["Properties"]["Name"]
        assert name.startswith("/app-d9fae51c-1929cc69/")


def test_ec2_discovery_schedule_rule_targets_the_ec2_discovery_function():
    rule = RESOURCES["Ec2DiscoveryScheduleRule"]["Properties"]
    assert rule["ScheduleExpression"] == "rate(30 minutes)"
    assert rule["State"] == "ENABLED"
    targets = rule["Targets"]
    assert len(targets) == 1
    assert targets[0]["Arn"] == {"Fn::GetAtt": "Ec2DiscoveryFunction.Arn"}


def test_ec2_discovery_invoke_permission_scoped_to_its_own_rule():
    perm = RESOURCES["Ec2DiscoveryInvokePermission"]["Properties"]
    assert perm["Principal"] == "events.amazonaws.com"
    assert perm["SourceArn"] == {"Fn::GetAtt": "Ec2DiscoveryScheduleRule.Arn"}
    assert perm["FunctionName"] == {"Fn::Ref": "Ec2DiscoveryFunction"}


def test_step_function_and_eventbridge_roles_have_the_deploy_boundary():
    boundary_arn = "arn:aws:iam::544635841962:policy/brd-architect-deploy-boundary"
    for logical_id in (
        "DiscoverySfnRole",
        "RenewalSfnRole",
        "RotationSfnRole",
        "PasswordResetSfnRole",
        "EventBridgeSfnRole",
    ):
        props = RESOURCES[logical_id]["Properties"]
        assert props["PermissionsBoundary"] == boundary_arn, (
            f"{logical_id}.PermissionsBoundary must be {boundary_arn!r}"
        )


def test_ssm_parameters_live_under_the_mandated_path():
    path_prefix = "/app-d9fae51c-1929cc69/"
    for logical_id, resource in RESOURCES.items():
        if resource.get("Type") != "AWS::SSM::Parameter":
            continue
        name = resource["Properties"]["Name"]
        assert name.startswith(path_prefix), f"{logical_id}.Name = {name!r}"


# ---------------------------------------------------------------------------
# Permissions regressions
# ---------------------------------------------------------------------------

SFN_ROLES = (
    "DiscoverySfnRole",
    "RenewalSfnRole",
    "RotationSfnRole",
    "PasswordResetSfnRole",
)


def test_no_acm_permissions_anywhere_in_the_template():
    """ACM is absent from CLAUDE.md's allowed-services list, so the account
    permissions boundary denies acm:* no matter what a role grants.

    Granting it anyway is worse than useless: the deploy succeeds, the call
    fails at runtime deep inside a state machine, and the AccessDeniedException
    only reaches the execution history. That is exactly how the Renew button
    came to return 202 and then do nothing.
    """
    offenders = []
    for logical_id, statement in _iter_statements():
        actions = statement["Action"]
        actions = [actions] if isinstance(actions, str) else actions
        for action in actions:
            if isinstance(action, str) and action.startswith("acm:"):
                offenders.append(f"{logical_id}: {action}")
    assert not offenders, (
        "these grants can never take effect — the permissions boundary denies "
        "ACM. Do not add the permission; remove the call.\n" + "\n".join(offenders)
    )


def test_every_state_machine_role_can_actually_write_xray_traces():
    """Each state machine sets Tracing.Enabled: true AND supplies its own Role.

    SAM only injects X-Ray permissions into a role it generates itself, so a
    custom Role leaves tracing enabled but unauthorised — it fails silently, with
    no trace and no error anywhere.
    """
    required = {
        "xray:PutTraceSegments",
        "xray:PutTelemetryRecords",
        "xray:GetSamplingRules",
        "xray:GetSamplingTargets",
    }
    for logical_id in SFN_ROLES:
        granted = set()
        for policy in RESOURCES[logical_id]["Properties"]["Policies"]:
            for statement in policy["PolicyDocument"]["Statement"]:
                actions = statement["Action"]
                granted.update([actions] if isinstance(actions, str) else actions)
        missing = required - granted
        assert not missing, f"{logical_id} enables tracing but cannot write it: {missing}"


def test_api_audit_can_describe_every_state_machine_it_is_asked_about():
    """GET /executions/{executionId} is the UI's only way to learn whether a
    renew/rotate/password-reset actually succeeded.

    PasswordResetSfn was missing from this grant, so polling an approved reset
    returned AccessDenied — indistinguishable in the browser from the execution
    itself having failed.
    """
    statements = [
        statement
        for logical_id, statement in _iter_statements()
        if logical_id == "ApiAuditFunction"
    ]
    described = []
    for statement in statements:
        actions = statement["Action"]
        actions = [actions] if isinstance(actions, str) else actions
        if not any(a.startswith("states:") for a in actions):
            continue
        resources = statement["Resource"]
        resources = [resources] if isinstance(resources, dict) else resources
        described.extend(str(r) for r in resources)

    joined = " ".join(described)
    for name in ("DiscoverySfn", "RenewalSfn", "RotationSfn", "PasswordResetSfn"):
        assert f"${{{name}.Name}}" in joined, (
            f"api-audit-fn cannot DescribeExecution on {name} — polling one of its "
            "executions returns AccessDenied, which looks like a failed execution"
        )
