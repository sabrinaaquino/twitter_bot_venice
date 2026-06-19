"""Hard tweet-length backstop on the agent path."""
import pytest

from config import Config
from agent.guardrails import fit_to_limit, agent_reply


class StubAgent:
    def __init__(self, reply):
        self._reply = reply
        self.calls = 0

    async def run(self, user_msg=None):
        self.calls += 1
        return self._reply


def test_under_limit_unchanged():
    assert fit_to_limit("short reply", 280) == "short reply"


def test_breaks_on_late_sentence_boundary():
    # boundary in the last ~30% → cut there cleanly (no ellipsis)
    text = "A" * 230 + ". " + "B" * 200
    out = fit_to_limit(text, 280)
    assert len(out) <= 280
    assert out == "A" * 230 + "."


def test_early_boundary_falls_through_to_hard_cut():
    # boundary too early (would discard most of the budget) → hard cut + ellipsis
    text = "Short. " + "x" * 400
    out = fit_to_limit(text, 280)
    assert len(out) <= 280
    assert out.endswith("…")


def test_hard_cut_when_no_boundary():
    text = "x" * 400
    out = fit_to_limit(text, 280)
    assert len(out) <= 280
    assert out.endswith("…")


def test_guardrail_truncates_overlong_reply():
    long_reply = "VVV is the Venice token and it is great. " * 20  # ~820 chars, benign
    agent = StubAgent(long_reply)
    res = agent_reply("what is vvv?", agent=agent)
    assert res.trip is None
    assert len(res.text) <= Config.char_limit()
