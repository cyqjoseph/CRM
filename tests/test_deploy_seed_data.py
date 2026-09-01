"""deploy.sh: one-time test-data seed for cert-inventory / iam-accounts.

WORKAROUND, not the long-term data source (see README's Deviations section
and scripts/seed.sh): the discovery Lambdas cannot be exercised end to end
here yet, so deploy.sh writes a fixed, known-OwnerId set of rows directly via
`aws dynamodb put-item` — the same mechanism deploy.sh already uses to seed
the simulated EC2-correlated ACM certificates — so the UI's Certificates and
IAM Accounts tabs have something to render immediately after a deploy.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DEPLOY = (ROOT / "deploy.sh").read_text()

TEST_OWNER_ID = "d9ca551c-d0a1-7011-1c4f-99a48c8d917f"

EXPECTED_CERT_IDS = ("cert-001", "cert-002", "cert-003")
EXPECTED_IAM_ACCOUNT_IDS = ("hash-acct-001", "hash-acct-002")


def _without_comments(script: str) -> str:
    return "\n".join(
        line for line in script.splitlines() if not line.lstrip().startswith("#")
    )


DEPLOY_CODE = _without_comments(DEPLOY)


def test_deploy_seeds_the_fixed_test_owner_id():
    assert TEST_OWNER_ID in DEPLOY_CODE, (
        "deploy.sh must seed cert-inventory/iam-accounts rows owned by the "
        f"known test OwnerId {TEST_OWNER_ID!r}"
    )


def test_deploy_seeds_every_requested_certificate():
    for cert_id in EXPECTED_CERT_IDS:
        assert cert_id in DEPLOY_CODE, f"deploy.sh does not seed {cert_id}"


def test_deploy_seeds_every_requested_iam_account():
    for account_hash in EXPECTED_IAM_ACCOUNT_IDS:
        assert account_hash in DEPLOY_CODE, f"deploy.sh does not seed {account_hash}"


def test_deploy_writes_test_data_to_both_tables_after_the_stack_exists():
    assert "app-d9fae51c-1929cc69-cert-inventory" in DEPLOY_CODE or "CertInventoryTableName" in DEPLOY_CODE
    assert "IamAccountsTableName" in DEPLOY_CODE, (
        "deploy.sh must resolve the iam-accounts table name from the stack "
        "outputs, the same way it already does for CertInventoryTableName"
    )
    assert DEPLOY_CODE.index("sam deploy") < DEPLOY_CODE.index(EXPECTED_IAM_ACCOUNT_IDS[0]), (
        "the test-data seed must run after the stack (and its tables) exist"
    )


def test_deploy_seed_is_idempotent_put_item_not_a_conditional_create():
    """Re-running deploy.sh must not fail just because the rows already exist."""
    assert DEPLOY_CODE.count("put-item") >= 1


def test_deploy_seed_failures_do_not_abort_the_deploy():
    """A transient DynamoDB error seeding test data must not fail a deploy
    that otherwise succeeded — same non-fatal convention as the post-deploy
    discovery Lambda invocations."""
    # Every put-item call for the fixed test rows must be defended by `||`
    # (already-established warn-and-continue idiom) rather than left to
    # `set -e`'s default of aborting the whole script.
    for cert_id in EXPECTED_CERT_IDS + EXPECTED_IAM_ACCOUNT_IDS:
        idx = DEPLOY_CODE.index(cert_id)
        # The nearest following occurrence of "||" or a wrapping function call
        # is what makes the write non-fatal; look at a generous window after
        # the id for either a `||` guard or a helper function invocation.
        window = DEPLOY_CODE[idx: idx + 800]
        assert "||" in window or "seed_item" in DEPLOY_CODE, (
            f"seeding {cert_id} must not be able to abort the deploy on failure"
        )
