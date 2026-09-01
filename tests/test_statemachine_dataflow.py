"""Every `$.field` a state reads must still exist by the time it runs.

This is the bug that made Renew look broken even after the ACM fix was in. A
Task state that omits `ResultPath` does not *add* its result to the execution
state — it REPLACES the whole thing. So:

    RenewCertificate            ResultPath: $.renewalResult   -> {certId, requestId, renewalResult}
    WriteRenewalSuccessAudit    ResultPath: <absent>          -> {SdkHttpMetadata, SdkResponseMetadata}
    PublishRenewalCompletion    reads $.renewalResult         -> States.Runtime, execution FAILED

The renewal itself had already succeeded and the audit event was already
written; only the final SNS publish blew up, two states later, on a field the
audit write had silently wiped out. Step Functions reports that as a plain
`ExecutionFailed`, so from the browser it is indistinguishable from the renewal
never having worked.

The invariant below is therefore: no Task state may implicitly discard the
execution state. Use an explicit `ResultPath` to graft the result on, or
`ResultPath: null` to keep the input and throw the result away.
"""
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
ASL_FILES = sorted((ROOT / "statemachines").glob("*.asl.json"))

assert ASL_FILES, "no state machine definitions found"


def _load(path):
    return json.loads(path.read_text())


def _states_with_a_result(definition):
    """States that produce a result ResultPath applies to (Fail/Succeed/Pass do not)."""
    return {
        name: state
        for name, state in definition["States"].items()
        if state["Type"] in ("Task", "Parallel", "Map")
    }


@pytest.mark.parametrize("path", ASL_FILES, ids=lambda p: p.name)
def test_every_result_producing_state_declares_a_resultpath(path):
    definition = _load(path)
    offenders = [
        name
        for name, state in _states_with_a_result(definition).items()
        if "ResultPath" not in state
    ]
    assert not offenders, (
        f"{path.name}: {offenders} omit ResultPath, so each one REPLACES the whole "
        "execution state with its own result and wipes out every field a later "
        'state reads. Add an explicit path, or "ResultPath": null to discard the '
        "result and pass the input through unchanged."
    )


def _referenced_fields(state):
    """Top-level `$.foo` fields this state reads from the execution state.

    Ignores `$$.` (the context object, always available) and bare `$`.
    """
    blob = json.dumps({k: v for k, v in state.items() if k in ("Parameters", "ItemsPath")})
    # `$.foo` / `$.foo.bar` but never `$$.Something`
    return set(re.findall(r"(?<!\$)\$\.([A-Za-z_][A-Za-z0-9_]*)", blob))


def _linear_chain(definition):
    """Walk StartAt through Next, following the happy path only."""
    chain, name, seen = [], definition["StartAt"], set()
    while name and name not in seen:
        seen.add(name)
        state = definition["States"][name]
        chain.append((name, state))
        name = state.get("Next")
    return chain


@pytest.mark.parametrize("path", ASL_FILES, ids=lambda p: p.name)
def test_no_state_reads_a_field_an_earlier_state_discarded(path):
    """Simulates ResultPath semantics down the happy path.

    Tracks whether the original execution input is still present, plus the
    fields each ResultPath has grafted on. A state with no ResultPath clobbers
    both — anything read after that point is unresolvable at runtime.
    """
    definition = _load(path)
    input_preserved = True
    added = set()
    errors = []

    for name, state in _linear_chain(definition):
        for field in _referenced_fields(state):
            if not input_preserved and field not in added:
                errors.append(
                    f"{name} reads $.{field}, but an earlier state replaced the "
                    "execution state (no ResultPath), so it no longer exists"
                )

        if state["Type"] not in ("Task", "Parallel", "Map"):
            continue
        if "ResultPath" not in state:
            input_preserved = False
            added = set()
        elif state["ResultPath"] is None:
            pass  # result discarded, input passed through untouched
        else:
            added.add(state["ResultPath"].removeprefix("$.").split(".")[0])

    assert not errors, f"{path.name}:\n  " + "\n  ".join(errors)


@pytest.mark.parametrize("path", ASL_FILES, ids=lambda p: p.name)
def test_definition_is_valid_json_and_every_next_target_exists(path):
    definition = _load(path)
    names = set(definition["States"])
    assert definition["StartAt"] in names

    for name, state in definition["States"].items():
        targets = []
        if state.get("Next"):
            targets.append(state["Next"])
        for catcher in state.get("Catch", []) or []:
            targets.append(catcher["Next"])
        for choice in state.get("Choices", []) or []:
            targets.append(choice["Next"])
        for target in targets:
            assert target in names, f"{path.name}: {name} -> unknown state {target!r}"


@pytest.mark.parametrize("path", ASL_FILES, ids=lambda p: p.name)
def test_every_failure_branch_records_an_audit_event(path):
    """A caught failure must leave a trace. The UI's only durable record of why
    a renew/rotate failed is the audit table."""
    definition = _load(path)
    for name, state in definition["States"].items():
        for catcher in state.get("Catch", []) or []:
            target = definition["States"][catcher["Next"]]
            assert "dynamodb:putItem" in json.dumps(target) or target["Type"] == "Fail", (
                f"{path.name}: {name}'s catch goes to {catcher['Next']}, which neither "
                "writes an audit event nor fails outright"
            )
