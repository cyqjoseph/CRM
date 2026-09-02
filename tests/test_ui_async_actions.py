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


def test_error_bodies_are_read_from_error_and_details_not_only_message():
    """api-executions-fn/api-certs-fn return {error, details} when they catch a
    specific AWS call; guard_api_handler returns {message}.

    Reading only `message` discarded `details` — the field holding the actual
    exception, often an AccessDeniedException naming the denied action — and
    turned every such failure into an opaque "request failed (500)".
    """
    assert "describeError" in APP_JS
    for field in ("body.error", "body.details", "body.message"):
        assert field in APP_JS, f"apiFetch ignores {field}"


def test_a_persistently_failing_poll_is_reported_not_swallowed():
    """The poller used to `continue` past every error and then claim the
    execution was "still running" — the same invisibility bug it was added to
    fix, one layer down."""
    assert "POLL_FAILED" in APP_JS
    assert "lastError" in APP_JS


def test_a_poll_failure_does_not_claim_the_action_itself_failed():
    """Only the status lookup failed; the renewal may well have succeeded."""
    start = APP_JS.index('outcome.status === "POLL_FAILED"')
    body = APP_JS[start : start + 600]
    assert "checking its status failed" in body
    assert "may still have succeeded" in body


def test_a_hopeless_poll_gives_up_early():
    """Any 4xx will never become a 200 — retrying it 20 times just makes the
    user wait 30s for an error already known on the first attempt."""
    assert "err.status >= 400 && err.status < 500" in APP_JS
