"""Stateful spam/security guard on State.

When a user trips a security screen (injection/scam) or floods us, they're
blocked for SPAM_BLOCK_HOURS. The block auto-expires (false positives get
re-listened to); re-offending re-blocks and escalates the offense count.
`now` is injected so tests don't depend on the wall clock.
"""
import pytest

from config import Config
from state import State

HOUR = 3600
WINDOW = Config.SPAM_BLOCK_HOURS * HOUR


@pytest.fixture
def state_file(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "STATE_FILE", str(tmp_path / "state.json"))


def test_unknown_user_not_blocked(state_file):
    s = State()
    assert s.is_blocked("u1", now=1000.0) is False
    assert s.times_offended("u1") == 0


def test_record_offense_blocks_within_window(state_file):
    s = State()
    s.record_offense("u1", now=1000.0)
    assert s.is_blocked("u1", now=1000.0) is True
    assert s.is_blocked("u1", now=1000.0 + WINDOW - 1) is True


def test_block_expires_and_is_pruned(state_file):
    s = State()
    s.record_offense("u1", now=1000.0)
    # After the window, no longer blocked...
    assert s.is_blocked("u1", now=1000.0 + WINDOW + 1) is False
    # ...and the expired entry was cleaned up (re-listening).
    assert "u1" not in s.blocked_until


def test_offense_count_escalates_and_survives_expiry(state_file):
    s = State()
    s.record_offense("u1", now=1000.0)
    assert s.times_offended("u1") == 1
    # Re-offend after expiry -> re-blocked, escalated.
    s.record_offense("u1", now=1000.0 + WINDOW + 10)
    assert s.times_offended("u1") == 2
    assert s.is_blocked("u1", now=1000.0 + WINDOW + 10) is True


def test_block_state_round_trips(state_file):
    s = State()
    s.record_offense("u1", now=1000.0)
    s.save()

    reloaded = State()
    reloaded.load()
    assert reloaded.is_blocked("u1", now=1000.0) is True
    assert reloaded.times_offended("u1") == 1
