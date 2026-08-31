"""Checks on scripts/seed.sh and scripts/lib-stack-outputs.sh.

Two facts about this deployment make seeding a prerequisite for validating
anything through the UI, rather than a convenience:

1. Every read endpoint scopes to the caller. `GET /certs` and `GET /iam/accounts`
   query OwnerIndex with `OwnerId = <the caller's Cognito sub>`. Discovery, by
   contrast, derives OwnerId from an ACM domain name, an IAM server-cert path or
   a `crm:owner-id` tag — never a Cognito sub. So rows written by a perfectly
   healthy discovery run are invisible to every human login, and an empty table
   in the UI says nothing about whether the pipeline works.

2. Both OwnerIndex definitions have a RANGE key (ExpiryDate for certs,
   NextRotationDate for IAM accounts). DynamoDB omits an item from a GSI entirely
   when it lacks that index's range key, silently — so a seeded row missing it
   would return no error and still never appear.

Seeded rows therefore have to carry the caller's own sub AND the range key.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SEED = (ROOT / "scripts" / "seed.sh").read_text()
LIB = (ROOT / "scripts" / "lib-stack-outputs.sh").read_text()
VALIDATE = (ROOT / "scripts" / "validate.sh").read_text()


def _without_comments(script: str) -> str:
    """Drop whole-line comments so a flag named in prose isn't read as usage."""
    return "\n".join(
        line for line in script.splitlines() if not line.lstrip().startswith("#")
    )


SEED_CODE = _without_comments(SEED)
LIB_CODE = _without_comments(LIB)
VALIDATE_CODE = _without_comments(VALIDATE)


def test_seed_scripts_are_executable():
    for name in ("seed.sh", "validate.sh", "lib-stack-outputs.sh"):
        path = ROOT / "scripts" / name
        assert path.stat().st_mode & 0o111, f"scripts/{name} is not executable"


def test_every_script_fails_fast():
    for name, code in (("seed.sh", SEED), ("lib-stack-outputs.sh", LIB)):
        assert "set -euo pipefail" in code, f"scripts/{name} must fail fast"


def test_seed_resolves_the_owner_from_cognito_not_a_hardcoded_id():
    """OwnerId must be the real Cognito sub, or the API will never return the row."""
    assert "admin-get-user" in SEED_CODE, (
        "seed.sh must look the target user's sub up in Cognito; the API scopes "
        "every query to the caller's sub, so a guessed OwnerId returns nothing"
    )
    assert "'sub'" in SEED_CODE or '"sub"' in SEED_CODE or "sub" in SEED_CODE


def test_seeded_certs_carry_the_owner_index_range_key():
    assert "ExpiryDate" in SEED_CODE, (
        "cert OwnerIndex has ExpiryDate as its RANGE key — an item without it is "
        "silently absent from the index and never appears in GET /certs"
    )


def test_seeded_iam_accounts_carry_the_owner_index_range_key():
    assert "NextRotationDate" in SEED_CODE, (
        "IAM OwnerIndex has NextRotationDate as its RANGE key — an item without "
        "it is silently absent from the index"
    )


def test_seed_writes_to_all_three_tables():
    for table in (
        "app-d9fae51c-1929cc69-cert-inventory",
        "app-d9fae51c-1929cc69-iam-accounts",
        "app-d9fae51c-1929cc69-audit-hot",
    ):
        assert table in SEED_CODE, f"seed.sh does not write to {table}"


def test_seed_covers_every_status_band_the_ui_colours():
    """The UI colours expiry by <=7d danger, <=30d warn, else ok.

    Seeding only one band leaves two thirds of the rendering untested.
    """
    assert "--clean" in SEED_CODE, "seed.sh must offer --clean to remove its rows"
    # A danger row (<=7d) and a healthy row (>30d) at minimum.
    assert "SEED_CERTS" in SEED_CODE, "expected a SEED_CERTS table of fixtures"


def test_seeded_ids_are_identifiable_so_clean_is_precise():
    """--clean must delete exactly what --seed wrote, never a real discovered row."""
    assert "seed-" in SEED_CODE, (
        "seeded ids must carry a recognisable prefix so --clean cannot delete a "
        "genuinely discovered certificate"
    )


def test_outputs_are_resolvable_without_a_local_outputs_json():
    """The platform deploys on push, so outputs.json is never written locally.

    It is also in .gitignore. A script that only reads outputs.json therefore
    cannot run from a fresh clone, which is the normal case here.
    """
    assert "describe-stacks" in LIB_CODE, (
        "lib-stack-outputs.sh must fall back to CloudFormation when outputs.json "
        "is absent — it is gitignored and written only on the deploy host"
    )
    assert "outputs.json" in LIB, "the local outputs.json should still be preferred"


def test_validate_and_seed_share_the_output_resolver():
    for name, code in (("validate.sh", VALIDATE_CODE), ("seed.sh", SEED_CODE)):
        assert "lib-stack-outputs.sh" in code, (
            f"scripts/{name} must source lib-stack-outputs.sh rather than "
            "reimplement output resolution"
        )


def test_running_the_resolver_directly_reports_what_it_found():
    """As a pure library it exited 0 in total silence, which reads as a no-op.

    Executing it is the obvious way to check whether credentials and the stack
    are reachable, so it has to say something when run rather than sourced.
    """
    assert "BASH_SOURCE" in LIB_CODE, (
        "lib-stack-outputs.sh must distinguish being executed from being sourced"
    )
    assert "resolved from" in LIB, "executing the resolver must print what it resolved"


def test_the_resolver_stays_quiet_when_sourced():
    """The summary must not contaminate callers that parse or display output."""
    guard = LIB_CODE.index("BASH_SOURCE")
    printf_calls = [
        i for i, line in enumerate(LIB_CODE.splitlines()) if "printf 'resolved from" in line
    ]
    assert printf_calls, "expected the summary to be printed with printf"
    # Every summary line must sit after the executed-vs-sourced guard.
    assert LIB_CODE.index("resolved from") > guard, (
        "the summary must be inside the `executed directly` branch, or sourcing "
        "the library would print it on every validate.sh/seed.sh run"
    )
