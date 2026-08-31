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
    ("/ad-accounts", "get"),
    ("/ad-accounts/{accountId}", "get"),
    ("/ad-accounts/{accountId}/rotate", "post"),
    ("/executions/{executionId}", "get"),
    ("/audit", "get"),
}

# Actions that AWS's IAM Service Authorization Reference documents as NOT
# supporting resource-level permissions at all — a wildcard Resource is the
# only valid value for these, not a scoping gap.
MANDATORY_WILDCARD_ACTIONS = {
    "acm:ListCertificates",
    "acm:DescribeCertificate",
    "secretsmanager:ListSecrets",
    "secretsmanager:DescribeSecret",
    "iam:ListServerCertificates",
    "ecr:GetAuthorizationToken",
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
    for name in ("DiscoverySfn", "RenewalSfn", "RotationSfn"):
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
    pass_role_seen = False
    for logical_id, statement in _iter_statements():
        actions = statement["Action"]
        actions = [actions] if isinstance(actions, str) else actions
        if "iam:PassRole" not in actions:
            continue
        pass_role_seen = True
        resource = statement["Resource"]
        resources = [resource] if isinstance(resource, (str, dict)) else resource
        assert resources != "*"
        for r in resources:
            assert r != "*", f"{logical_id} grants iam:PassRole on a wildcard resource"
    assert pass_role_seen, "expected at least one iam:PassRole statement in the template"


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


def test_ssm_parameters_live_under_the_mandated_path():
    path_prefix = "/app-d9fae51c-1929cc69/"
    for logical_id, resource in RESOURCES.items():
        if resource.get("Type") != "AWS::SSM::Parameter":
            continue
        name = resource["Properties"]["Name"]
        assert name.startswith(path_prefix), f"{logical_id}.Name = {name!r}"
