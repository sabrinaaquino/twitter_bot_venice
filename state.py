"""Persistent state — tracks processed tweets and per-conversation author locks."""
import json
from config import Config


class State:
    def __init__(self):
        self.processed: set[str] = set()
        self.allowed_authors: dict[str, str] = {}  # conversation_id → author_id

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
        except FileNotFoundError:
            pass

    def save(self):
        with open(Config.STATE_FILE, "w") as f:
            json.dump(
                {
                    "processed_tweets": list(self.processed),
                    "allowed_authors": self.allowed_authors,
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
