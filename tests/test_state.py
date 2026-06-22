"""Finding B — bounded, less-frequent state persistence.

State should:
- dedup processed tweet IDs (membership, no duplicate growth)
- cap the processed set and the allowed-authors map, evicting oldest first
- only write to disk when something actually changed (dirty tracking)
- round-trip cleanly through save()/load()

Tests point Config.STATE_FILE at a tmp file so they never touch the real one.
"""
import json

import pytest

from config import Config
from state import State


@pytest.fixture
def state_file(tmp_path, monkeypatch):
    path = tmp_path / "state.json"
    monkeypatch.setattr(Config, "STATE_FILE", str(path))
    return path


# ── Basic behaviour ───────────────────────────────────────────────

def test_add_and_is_processed(state_file):
    s = State()
    assert not s.is_processed("123")
    s.add_tweet("123")
    assert s.is_processed("123")


def test_add_tweet_dedups(state_file):
    s = State()
    s.add_tweet("123")
    s.add_tweet("123")
    s.save()
    reloaded = State()
    reloaded.load()
    # only one entry persisted
    assert json_processed_count(state_file) == 1


# ── Dirty tracking: only write when changed ───────────────────────

def test_save_is_noop_when_not_dirty(state_file):
    s = State()
    s.load()                      # missing file -> empty, clean
    s.save()
    assert not state_file.exists(), "clean state must not write a file"


def test_save_writes_when_dirty(state_file):
    s = State()
    s.add_tweet("999")
    s.save()
    assert state_file.exists()


def test_save_noop_after_reload_without_changes(state_file):
    # seed a file
    s = State()
    s.add_tweet("1")
    s.save()
    mtime = state_file.stat().st_mtime_ns

    # reload, change nothing, save -> file must not be rewritten
    s2 = State()
    s2.load()
    s2.save()
    assert state_file.stat().st_mtime_ns == mtime


# ── Bounded growth ────────────────────────────────────────────────

def test_processed_is_capped_evicting_oldest(state_file, monkeypatch):
    monkeypatch.setattr(Config, "MAX_PROCESSED_TWEETS", 5)
    s = State()
    for i in range(1, 11):        # add "1".."10"
        s.add_tweet(str(i))
    s.save()

    reloaded = State()
    reloaded.load()
    assert json_processed_count(state_file) == 5
    # oldest evicted, most-recent kept
    assert not reloaded.is_processed("1")
    assert reloaded.is_processed("10")


def test_allowed_authors_is_capped(state_file, monkeypatch):
    monkeypatch.setattr(Config, "MAX_ALLOWED_AUTHORS", 3)
    s = State()
    for i in range(1, 7):         # 6 conversations
        s.set_allowed_author(f"conv{i}", f"author{i}")
    s.save()

    reloaded = State()
    reloaded.load()
    with open(state_file) as f:
        data = json.load(f)
    assert len(data["allowed_authors"]) == 3
    assert reloaded.get_allowed_author("conv6") == "author6"
    assert reloaded.get_allowed_author("conv1") is None


# ── Round-trip ────────────────────────────────────────────────────

def test_round_trip(state_file):
    s = State()
    s.add_tweet("42")
    s.set_allowed_author("convA", "authA")
    s.save()

    reloaded = State()
    reloaded.load()
    assert reloaded.is_processed("42")
    assert reloaded.get_allowed_author("convA") == "authA"


# ── helpers ───────────────────────────────────────────────────────

def json_processed_count(path):
    with open(path) as f:
        return len(json.load(f)["processed_tweets"])
