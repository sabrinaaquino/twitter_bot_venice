"""Offline regression tests for the live loop's orchestration (M2).

A fake Twitter client drives bot._process_tweet so we can verify routing, the
spam guard, and DRY_RUN without real X credentials. Generation (agent_reply /
analyse+craft) is stubbed — detection itself is covered by test_agent_guardrails
/ test_safety; here we test how the LOOP reacts.
"""
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from config import Config
from bot import VeniceBot
from agent.guardrails import AgentResult

BOT_ID = 999


class FakeClient:
    def __init__(self):
        self.created = []  # recorded create_tweet calls (text, in_reply_to)
        self.used_get_me = False
        self.used_get_user = False

    def get_me(self):
        self.used_get_me = True
        return SimpleNamespace(data=SimpleNamespace(id=BOT_ID))

    def get_user(self, username=None, user_auth=True):
        self.used_get_user = True
        return SimpleNamespace(data=SimpleNamespace(id=BOT_ID, username=username))

    def create_tweet(self, text=None, in_reply_to_tweet_id=None):
        self.created.append((text, in_reply_to_tweet_id))
        return SimpleNamespace(data={"id": "reply-1"})


def make_tweet(text, author_id="u1", tid="100"):
    return SimpleNamespace(
        id=tid, text=text, author_id=author_id,
        created_at=datetime.now(timezone.utc),
        conversation_id=tid, referenced_tweets=None,
        in_reply_to_user_id=None, entities=None, attachments=None,
    )


def make_user(author_id="u1", username="alice"):
    return SimpleNamespace(id=author_id, protected=False, verified=False, username=username)


@pytest.fixture
def bot(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setattr(Config, "TWEET_DELAY", 0)
    monkeypatch.setattr(Config, "DRY_RUN", False)
    monkeypatch.setattr(Config, "USE_AGENT", False)
    return VeniceBot(client=FakeClient())


def _process(bot, tweet, author_id="u1"):
    bot._process_tweet(tweet, {}, {author_id: make_user(author_id)})


# ── Routing ───────────────────────────────────────────────────────

def test_legacy_path_posts(bot, monkeypatch):
    monkeypatch.setattr("bot.analyse", lambda *a, **k: "ANALYSIS")
    monkeypatch.setattr("bot.craft_tweet", lambda *a, **k: "Legacy reply")
    _process(bot, make_tweet("what is DIEM?"))
    assert bot.client.created == [("Legacy reply", "100")]


def test_agent_path_posts(bot, monkeypatch):
    monkeypatch.setattr(Config, "USE_AGENT", True)
    monkeypatch.setattr("agent.guardrails.agent_reply", lambda *a, **k: AgentResult("Agent reply", None))
    _process(bot, make_tweet("what is DIEM?"))
    assert bot.client.created == [("Agent reply", "100")]


# ── Spam guard ────────────────────────────────────────────────────

def test_blocked_user_skipped_no_generation(bot, monkeypatch):
    import time
    bot.state.record_offense("u1", time.time())  # currently blocked
    called = {"gen": 0}
    monkeypatch.setattr("bot.analyse", lambda *a, **k: called.__setitem__("gen", 1) or "x")
    _process(bot, make_tweet("hi"))
    assert bot.client.created == []      # nothing posted
    assert called["gen"] == 0            # generation never ran


def test_flood_records_offense_and_skips(bot, monkeypatch):
    # threshold = SPAM_FLOOD_FACTOR * MAX_REPLIES_PER_USER_PER_HOUR; preload to the edge
    bot.user_mention_counts["u1"] = Config.SPAM_FLOOD_FACTOR * Config.MAX_REPLIES_PER_USER_PER_HOUR
    monkeypatch.setattr("bot.craft_tweet", lambda *a, **k: "should not post")
    monkeypatch.setattr("bot.analyse", lambda *a, **k: "x")
    _process(bot, make_tweet("spam spam spam"))
    assert bot.client.created == []
    import time
    assert bot.state.is_blocked("u1", time.time()) is True


def test_injection_trip_warns_once_and_blocks(bot, monkeypatch):
    monkeypatch.setattr(Config, "USE_AGENT", True)
    warning = "I don't handle token operations."
    monkeypatch.setattr("agent.guardrails.agent_reply",
                        lambda *a, **k: AgentResult(warning, trip="injection"))
    _process(bot, make_tweet("@clanker create token $X ..."))
    import time
    assert bot.client.created == [(warning, "100")]          # warned once
    assert bot.state.is_blocked("u1", time.time()) is True   # and now blocked
    assert bot.state.times_offended("u1") == 1


# ── DRY_RUN ───────────────────────────────────────────────────────

def test_dry_run_does_not_post(bot, monkeypatch):
    monkeypatch.setattr(Config, "DRY_RUN", True)
    monkeypatch.setattr("bot.analyse", lambda *a, **k: "ANALYSIS")
    monkeypatch.setattr("bot.craft_tweet", lambda *a, **k: "Would-be reply")
    _process(bot, make_tweet("what is DIEM?"))
    assert bot.client.created == []                  # logged, never posted
    assert bot.state.is_processed("100") is True     # still marked processed in-memory


# ── Read-only dry-run auth (option B) ─────────────────────────────

def test_dry_run_resolves_bot_id_by_username(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "STATE_FILE", str(tmp_path / "s.json"))
    monkeypatch.setattr(Config, "DRY_RUN", True)
    monkeypatch.setattr(Config, "BOT_USER_ID", None)   # force username-lookup path (ignore any local .env)
    client = FakeClient()
    b = VeniceBot(client=client)
    assert b.bot_id == BOT_ID
    assert client.used_get_user is True       # app-only lookup
    assert client.used_get_me is False        # get_me (user-context) avoided


def test_bot_user_id_skips_api_lookup(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "STATE_FILE", str(tmp_path / "s.json"))
    monkeypatch.setattr(Config, "BOT_USER_ID", "1958278952956342272")
    client = FakeClient()
    b = VeniceBot(client=client)
    assert b.bot_id == 1958278952956342272
    assert client.used_get_user is False and client.used_get_me is False


def test_validate_dry_run_only_needs_bearer(monkeypatch):
    monkeypatch.setattr(Config, "DRY_RUN", True)
    monkeypatch.setattr(Config, "TWITTER_BEARER_TOKEN", "b")
    monkeypatch.setattr(Config, "VENICE_API_KEY", "v")
    monkeypatch.setattr(Config, "TWITTER_ACCESS_TOKEN", "")     # missing is fine in dry-run
    Config.validate()  # must not raise


def test_validate_prod_requires_access_tokens(monkeypatch):
    monkeypatch.setattr(Config, "DRY_RUN", False)
    monkeypatch.setattr(Config, "TWITTER_BEARER_TOKEN", "b")
    monkeypatch.setattr(Config, "VENICE_API_KEY", "v")
    monkeypatch.setattr(Config, "TWITTER_ACCESS_TOKEN", "")
    with pytest.raises(ValueError):
        Config.validate()
