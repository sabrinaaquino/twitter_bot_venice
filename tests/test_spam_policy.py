"""Spam-policy helpers used by the live loop (pure, offline)."""
import pytest

from agent.guardrails import AgentResult, offense_reply_text, is_flood


def test_warn_once_then_silent():
    r = AgentResult("⚠️ I don't handle token operations.", trip="injection")
    assert offense_reply_text(r, prior_offenses=0) == r.text   # first offense → warn
    assert offense_reply_text(r, prior_offenses=1) is None      # re-offense → silent
    assert offense_reply_text(r, prior_offenses=5) is None


@pytest.mark.parametrize(
    "mentions, cap, factor, expected",
    [
        (6, 3, 2, False),   # exactly at the threshold (2*3) → not yet flooding
        (7, 3, 2, True),    # over the threshold → flooding
        (3, 3, 2, False),
        (100, 3, 2, True),
    ],
)
def test_is_flood(mentions, cap, factor, expected):
    assert is_flood(mentions, cap, factor) is expected
