"""The Renew / Rotate buttons must report an outcome, not just "started".

Both endpoints return 202 the instant the state machine starts. The UI used to
set the button to "Renewal started" and stop there, so every asynchronous
failure — a boundary-denied API call, a deleted row, a Lambda error — was
indistinguishable from the button doing nothing at all. That is the symptom that
made a broken renewal look like a broken button.

These are source-level assertions (there is no JS test runner in this repo), but
they pin the specific behaviours that made the failure invisible.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP_JS = (ROOT / "ui" / "app.js").read_text()


def test_the_ui_polls_the_execution_endpoint():
    assert "/executions/" in APP_JS, (
        "the UI must poll GET /executions/{executionId} — without it a 202 is the "
        "last thing it ever learns about a renew/rotate"
    )
    assert "awaitExecution" in APP_JS


def test_renew_and_rotate_both_go_through_the_polling_helper():
    for fn in ("renewCert", "rotateAccount"):
        start = APP_JS.index(f"function {fn}(")
        body = APP_JS[start : start + 500]
        assert "runAsyncAction" in body, f"{fn} does not await its execution outcome"


def test_a_failed_execution_surfaces_an_error_rather_than_a_success_label():
    """The old code had no branch for this at all."""
    assert 'outcome.status === "SUCCEEDED"' in APP_JS, (
        "the UI must distinguish a succeeded execution from a failed one"
    )
    assert "failed (${outcome.status})" in APP_JS


def test_a_successful_action_reloads_the_table():
    """Renewal writes a new ExpiryDate and rotation a new Status. Without a
    reload the row keeps showing the stale value, so a working action still looks
    like it did nothing."""
    assert "await reload()" in APP_JS


def test_the_poller_is_bounded():
    """An unbounded poll loop would hang the button forever on a stuck execution."""
    assert "POLL_MAX_ATTEMPTS" in APP_JS
    assert "TIMED_OUT" in APP_JS
