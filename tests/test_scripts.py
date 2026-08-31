"""Checks on deploy.sh / destroy.sh that don't require a live AWS account.

These cover the failure mode that produced a full stack rollback in which every
resource reported only "Resource creation cancelled":

CloudFormation's DeleteStack does not purge an AWS::SecretsManager::Secret — it
only schedules it for deletion behind a recovery window (30 days by default).
The secret name stays reserved for that whole window, so the next deploy's
CREATE of the same name fails immediately. Both secrets in template.yaml are
dependency-free, which puts them in CloudFormation's first creation wave next to
the tables, buckets, topics and queues; when one fails there, every sibling in
that wave is stamped "Resource creation cancelled" and the real reason never
appears against a resource anyone would look at.

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

# The two AWS::SecretsManager::Secret names in template.yaml.
SECRET_NAMES = (
    "app-d9fae51c-1929cc69-ad-bind-creds",
    "app-d9fae51c-1929cc69-jira-token",
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
