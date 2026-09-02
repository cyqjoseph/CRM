"""Checks on deploy.sh / destroy.sh that don't require a live AWS account.

These cover the failure mode that produced a full stack rollback in which every
resource reported only "Resource creation cancelled":

CloudFormation's DeleteStack does not purge an AWS::SecretsManager::Secret — it
only schedules it for deletion behind a recovery window (30 days by default).
The secret name stays reserved for that whole window, so the next deploy's
CREATE of the same name fails immediately. JiraTokenSecret is dependency-free,
which puts it in CloudFormation's first creation wave next to the tables,
buckets, topics and queues; when it fails there, every sibling in that wave is
stamped "Resource creation cancelled" and the real reason never appears
against a resource anyone would look at.

So: deploy.sh must reconcile that state before deploying, destroy.sh must not
leave it behind, and a failed deploy must print the root failure reasons rather
than the cascade of cancellations.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DEPLOY = (ROOT / "deploy.sh").read_text()
DESTROY = (ROOT / "destroy.sh").read_text()


def _without_comments(script: str) -> str:
    """Drop whole-line comments so a flag named in prose isn't read as usage."""
    return "\n".join(
        line for line in script.splitlines() if not line.lstrip().startswith("#")
    )

# The AWS::SecretsManager::Secret names in template.yaml.
SECRET_NAMES = (
    "app-d9fae51c-1929cc69-jira-token",
    "app-d9fae51c-1929cc69-password-reset-credentials",
)


def test_deploy_purges_secrets_left_scheduled_for_deletion():
    code = _without_comments(DEPLOY)
    assert "restore-secret" in code, (
        "deploy.sh must restore a secret scheduled for deletion before purging "
        "it; delete-secret --force-delete-without-recovery is rejected on a "
        "secret that is already scheduled for deletion"
    )
    assert "--force-delete-without-recovery" in code
    # The purge has to run before the stack deploy, or it cannot unblock it.
    assert code.index("--force-delete-without-recovery") < code.index("sam deploy"), (
        "the secret purge must run before `sam deploy`"
    )


def test_destroy_purges_secrets_after_deleting_the_stack():
    code = _without_comments(DESTROY)
    assert "--force-delete-without-recovery" in code, (
        "destroy.sh must purge the secrets outright; DeleteStack only schedules "
        "them, which blocks the next deploy for the whole recovery window"
    )
    assert code.index("delete-stack") < code.index("--force-delete-without-recovery"), (
        "purge the secrets after DeleteStack, otherwise the stack delete "
        "re-schedules them"
    )


def test_both_scripts_cover_every_secret_in_the_template():
    for script_name, script in (("deploy.sh", DEPLOY), ("destroy.sh", DESTROY)):
        for secret in SECRET_NAMES:
            assert secret in script, f"{script_name} does not handle {secret}"


def test_deploy_reports_root_cloudformation_failures_not_just_cancellations():
    code = _without_comments(DEPLOY)
    assert "describe-stack-events" in code, (
        "deploy.sh must dump stack events when the deploy fails — otherwise the "
        "build log shows only the cascade of cancellations"
    )
    # The cancellation noise has to be filtered out, or the root cause is buried
    # again by the dozens of resources that were merely cancelled.
    assert "Resource creation cancelled" in code, (
        "deploy.sh must exclude 'Resource creation cancelled' events when "
        "reporting the root failure"
    )


def test_deploy_never_uses_the_shared_sam_managed_bucket():
    # Per CLAUDE.md: the deploy role is scoped to app-d9fae51c-1929cc69-* stacks,
    # so the shared aws-sam-cli-managed-default stack is always AccessDenied.
    code = _without_comments(DEPLOY)
    assert "--resolve-s3" not in code
    assert "--guided" not in code
    assert "app-d9fae51c-1929cc69-artifacts" in code


def test_deploy_invokes_both_discovery_lambdas_after_the_stack_is_up():
    # cert-inventory/iam-accounts are otherwise empty until the daily
    # DiscoveryScheduleRule fires; invoking the real discovery Lambdas once
    # right after deploy gives both tables data immediately.
    code = _without_comments(DEPLOY)
    assert "app-d9fae51c-1929cc69-discovery-iam-fn" in code
    assert "app-d9fae51c-1929cc69-discovery-acm-fn" in code
    assert code.count("aws lambda invoke") == 3
    # CLI v2 requires this for a blob (Payload) parameter passed as raw JSON.
    assert "--cli-binary-format raw-in-base64-out" in code
    # A discovery Lambda failing must never fail the whole deploy.
    assert code.index("sam deploy") < code.index("discovery-iam-fn"), (
        "the discovery Lambdas must be invoked after the stack exists"
    )


def test_deploy_invokes_the_ec2_discovery_lambda_after_the_stack_is_up():
    # Same reasoning as the IAM/ACM discovery Lambdas: confirm the SSM dispatch
    # works right after deploy instead of waiting for the first scheduled tick.
    code = _without_comments(DEPLOY)
    assert "app-d9fae51c-1929cc69-ec2-discovery-fn" in code
    call = code[code.index("app-d9fae51c-1929cc69-ec2-discovery-fn"):][:400]
    assert "||" in call, "an ec2-discovery-fn invocation failure must warn and continue, not exit non-zero"
    assert code.index("sam deploy") < code.index("app-d9fae51c-1929cc69-ec2-discovery-fn"), (
        "the ec2-discovery Lambda must be invoked after the stack exists"
    )


def test_deploy_never_expands_acm_permissions_beyond_the_allowed_boundary():
    # ACM is not in CLAUDE.md's exhaustive allowed-services list, so the account
    # permissions boundary denies it on purpose. deploy.sh must not attempt to
    # work around that by touching IAM policies/boundaries at deploy time.
    code = _without_comments(DEPLOY)
    assert "put-role-policy" not in code
    assert "attach-role-policy" not in code
    assert "brd-architect-deploy-boundary" not in code


def test_deploy_seeds_demo_data_through_the_seeder_script():
    """deploy.sh used to carry ~130 lines of hand-written put-item heredocs with
    hardcoded 2025 dates, which silently aged into the past and made every seeded
    row render as long expired."""
    code = _without_comments(DEPLOY)
    assert "scripts/seed-demo-data.sh" in code
    assert code.index("sam deploy") < code.index("scripts/seed-demo-data.sh"), (
        "the tables must exist before anything is written to them"
    )


def test_deploy_seeding_cannot_abort_an_otherwise_successful_deploy():
    code = _without_comments(DEPLOY)
    call = code[code.index("scripts/seed-demo-data.sh"):][:400]
    assert "||" in call, "a seeding failure must warn and continue, not exit non-zero"


def test_seed_volume_and_owner_are_overridable_without_editing_the_script():
    code = _without_comments(DEPLOY)
    for var in ("SEED_OWNER_ID", "SEED_CERTS", "SEED_ACCOUNTS", "SEED_AUDIT_EVENTS"):
        assert var in code, f"{var} must be settable from the environment"


def test_deploy_seeds_one_shared_partition_not_a_copy_per_login():
    """The reported bug: team members signed into the same CRM saw different
    certificates, or none.

    OwnerId is OwnerIndex's HASH key, so seeding it with a Cognito sub gives that
    one login a private dashboard. deploy.sh used to do exactly that, twice, with
    different volumes per sub (40 certs for one, 3 for the other). There must be
    exactly one seeding call now, and it must target the shared partition.
    """
    code = _without_comments(DEPLOY)
    assert 'SEED_OWNER_ID="${SEED_OWNER_ID:-crm-resource-owners}"' in code, (
        "the seed must default to the shared team partition every login reads"
    )
    seed_calls = [
        line for line in code.splitlines()
        if "scripts/seed-demo-data.sh" in line and "--clean" not in line
        and "--retire-legacy-fixed-rows" not in line
    ]
    assert len(seed_calls) == 1, f"expected one seeding call, found {len(seed_calls)}: {seed_calls}"
    assert "SEED_EXTRA_OWNER_ID" not in code, (
        "seeding a second individual login is the bug, not a feature"
    )


def test_deploy_retires_the_rows_left_owned_by_an_individual_login():
    """Cleaning is what stops each member seeing their own private leftovers on
    top of the shared inventory — the same inconsistency in a quieter form. Demo
    ids are deterministic, so clean-then-seed leaves exactly one copy of each row."""
    code = _without_comments(DEPLOY)
    for sub in ("d9ca551c-d0a1-7011-1c4f-99a48c8d917f", "c90a255c-3071-708a-2806-987b385b1376"):
        assert sub in code, f"{sub} was seeded per-login and must be retired"
    assert "--clean" in code
    assert code.index("--clean") < code.rindex('--certs "$SEED_CERTS"'), (
        "the per-login rows must be cleaned BEFORE the shared partition is seeded, "
        "or the clean removes what was just written"
    )


def test_deploy_retires_the_fixed_rows_an_earlier_script_left_behind():
    """cert-001/002/003 and hash-acct-001/002 were written by a deploy.sh that no
    longer exists (commit 6e12d0d). Nothing owns them, nothing updates them, and
    they carry a status vocabulary no query in this application uses."""
    code = _without_comments(DEPLOY)
    assert "--retire-legacy-fixed-rows" in code
    call = code[code.index("--retire-legacy-fixed-rows"):][:300]
    assert "||" in call, "retiring the legacy rows must warn and continue, not exit non-zero"


def test_legacy_row_retirement_names_ids_individually_rather_than_by_prefix():
    """These ids lack the `demo-` prefix that makes every other id in the seeding
    path safe to match by pattern. An id-by-id list cannot widen into something
    that reaches a genuinely discovered certificate."""
    generator = (ROOT / "scripts" / "gen_demo_data.py").read_text()
    assert 'LEGACY_FIXED_CERT_IDS = ("cert-001", "cert-002", "cert-003")' in generator
    assert 'LEGACY_FIXED_ACCOUNT_IDS = ("hash-acct-001", "hash-acct-002")' in generator
    # And no ad-hoc delete calls in the shell path, which is what would let this
    # widen: everything goes through the generator's DeleteRequests.
    assert "delete-item" not in _without_comments(DEPLOY)
    assert "delete-item" not in _without_comments((ROOT / "scripts" / "seed-demo-data.sh").read_text())


def test_deploy_retries_ec2_discovery_because_it_races_the_instance_boot():
    """A new or replaced instance has to finish cloud-init, generate its internal
    CA and sign a certificate per host, then register with SSM. A single early
    invocation returns zero certificates, which is indistinguishable from a broken
    scan."""
    code = _without_comments(DEPLOY)
    assert "EC2_DISCOVERY_ATTEMPTS" in code
    assert "appCerts" in code, (
        "the retry must key on application certificates specifically — the trust "
        "store yields rows even when the certificate-issuing step failed"
    )


def test_seeder_only_ever_deletes_its_own_rows():
    """--clean must be incapable of removing a genuinely discovered resource."""
    seeder = (ROOT / "scripts" / "seed-demo-data.sh").read_text()
    generator = (ROOT / "scripts" / "gen_demo_data.py").read_text()
    assert "--delete" in seeder, "--clean must go through the generator, not ad-hoc deletes"
    assert 'DEMO_PREFIX = "demo-"' in generator
    # No unscoped destructive DynamoDB calls anywhere in the seeding path.
    for name, script in (("seed-demo-data.sh", seeder), ("gen_demo_data.py", generator)):
        assert "delete-table" not in script, f"{name} must never delete a table"
        assert "scan" not in script.lower() or name.endswith(".py"), name
