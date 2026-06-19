"""Persistent state — processed tweets, per-conversation author locks, and a
stateful spam/security blocklist with a TTL.

The spam guard blocks a user (by id) when they trip a security screen
(injection/scam) or flood us. The block auto-expires after Config.SPAM_BLOCK_HOURS
so false positives get re-listened to; re-offending re-blocks and escalates the
offense count. Callers pass `now` (epoch seconds) so behaviour is testable.
"""
import json
from config import Config


class State:
    def __init__(self):
        self.processed: set[str] = set()
        self.allowed_authors: dict[str, str] = {}  # conversation_id → author_id
        self.blocked_until: dict[str, float] = {}   # user_id → epoch seconds
        self.offense_count: dict[str, int] = {}     # user_id → lifetime offenses

    def load(self):
        try:
            with open(Config.STATE_FILE, "r") as f:
                data = json.load(f)
            if isinstance(data, list):
                self.processed = {str(t) for t in data}
                self.allowed_authors = {}
            elif isinstance(data, dict):
                self.processed = {str(t) for t in data.get("processed_tweets", [])}
                self.allowed_authors = {
                    str(k): str(v) for k, v in data.get("allowed_authors", {}).items()
                }
                self.blocked_until = {
                    str(k): float(v) for k, v in data.get("blocked_until", {}).items()
                }
                self.offense_count = {
                    str(k): int(v) for k, v in data.get("offense_count", {}).items()
                }
        except FileNotFoundError:
            pass

    def save(self):
        with open(Config.STATE_FILE, "w") as f:
            json.dump(
                {
                    "processed_tweets": list(self.processed),
                    "allowed_authors": self.allowed_authors,
                    "blocked_until": self.blocked_until,
                    "offense_count": self.offense_count,
                },
                f,
            )

    def is_processed(self, tweet_id) -> bool:
        return str(tweet_id) in self.processed

    def add_tweet(self, tweet_id):
        self.processed.add(str(tweet_id))

    def get_allowed_author(self, convo_id) -> str | None:
        return self.allowed_authors.get(str(convo_id))

    def set_allowed_author(self, convo_id, author_id):
        self.allowed_authors[str(convo_id)] = str(author_id)

    # ── Spam / security guard ────────────────────────────────────

    def is_blocked(self, user_id, now: float) -> bool:
        """True if the user is currently blocked. Expired blocks are pruned
        (so they get re-listened to — handles false positives)."""
        uid = str(user_id)
        until = self.blocked_until.get(uid)
        if until is None:
            return False
        if now >= until:
            del self.blocked_until[uid]  # auto-cleanup; offense history kept
            return False
        return True

    def record_offense(self, user_id, now: float):
        """Record a security/spam offense and (re)block the user for the
        configured window. Offense count escalates and persists across expiry."""
        uid = str(user_id)
        self.offense_count[uid] = self.offense_count.get(uid, 0) + 1
        self.blocked_until[uid] = now + Config.SPAM_BLOCK_HOURS * 3600

    def times_offended(self, user_id) -> int:
        return self.offense_count.get(str(user_id), 0)
