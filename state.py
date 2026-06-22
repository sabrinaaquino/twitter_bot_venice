"""Persistent state — tracks processed tweets and per-conversation author locks.

Bounded + dirty-tracked: the processed-tweet set and conversation-author map are
capped (oldest evicted first), and save() only writes when something changed —
mentions only arrive from the recent lookback window, so unbounded history just
bloats the file and the working tree.
"""
import json
from config import Config


class State:
    def __init__(self):
        # Insertion-ordered "set" of processed tweet IDs (dict keys preserve order
        # and give O(1) membership). Oldest = first inserted = front of the dict.
        self.processed: dict[str, None] = {}
        self.allowed_authors: dict[str, str] = {}  # conversation_id → author_id
        self._dirty = False

    def load(self):
        try:
            with open(Config.STATE_FILE, "r") as f:
                data = json.load(f)
            if isinstance(data, list):
                self.processed = {str(t): None for t in data}
                self.allowed_authors = {}
            elif isinstance(data, dict):
                self.processed = {str(t): None for t in data.get("processed_tweets", [])}
                self.allowed_authors = {
                    str(k): str(v) for k, v in data.get("allowed_authors", {}).items()
                }
        except FileNotFoundError:
            pass
        self._dirty = False

    def save(self):
        if not self._dirty:
            return
        self._prune()
        with open(Config.STATE_FILE, "w") as f:
            json.dump(
                {
                    "processed_tweets": list(self.processed.keys()),
                    "allowed_authors": self.allowed_authors,
                },
                f,
            )
        self._dirty = False

    def _prune(self):
        """Evict oldest entries beyond the configured caps."""
        excess = len(self.processed) - Config.MAX_PROCESSED_TWEETS
        for _ in range(max(0, excess)):
            self.processed.pop(next(iter(self.processed)))

        excess = len(self.allowed_authors) - Config.MAX_ALLOWED_AUTHORS
        for _ in range(max(0, excess)):
            self.allowed_authors.pop(next(iter(self.allowed_authors)))

    def is_processed(self, tweet_id) -> bool:
        return str(tweet_id) in self.processed

    def add_tweet(self, tweet_id):
        tid = str(tweet_id)
        if tid not in self.processed:
            self.processed[tid] = None
            self._dirty = True

    def get_allowed_author(self, convo_id) -> str | None:
        return self.allowed_authors.get(str(convo_id))

    def set_allowed_author(self, convo_id, author_id):
        cid, aid = str(convo_id), str(author_id)
        if self.allowed_authors.get(cid) != aid:
            self.allowed_authors[cid] = aid
            self._dirty = True
