"""Twitter API wrappers — mentions, replies, tweet lookup."""
import logging
import tweepy
from config import Config

logger = logging.getLogger(__name__)

_TWEET_FIELDS = [
    "created_at", "author_id", "attachments", "public_metrics",
    "conversation_id", "referenced_tweets", "in_reply_to_user_id", "entities",
]
_EXPANSIONS = [
    "attachments.media_keys", "author_id",
    "in_reply_to_user_id", "referenced_tweets.id",
]
_MEDIA_FIELDS = ["type", "url", "preview_image_url"]
_USER_FIELDS = ["protected", "verified", "username"]


def get_mentions(client: tweepy.Client, bot_user_id: int, *, start_time: str = None):
    kwargs = {
        "id": bot_user_id,
        "max_results": Config.MAX_MENTIONS_PER_CHECK,
        "tweet_fields": _TWEET_FIELDS,
        "expansions": _EXPANSIONS,
        "media_fields": _MEDIA_FIELDS,
        "user_fields": _USER_FIELDS,
    }
    if start_time:
        kwargs["start_time"] = start_time
    return client.get_users_mentions(**kwargs)


def reply_to_tweet(client: tweepy.Client, tweet_id: int, text: str):
    char_limit = Config.char_limit()

    if len(text) <= char_limit:
        try:
            resp = client.create_tweet(text=text, in_reply_to_tweet_id=tweet_id)
            logger.info(f"Replied to {tweet_id} → {resp.data['id']}")
            return resp
        except tweepy.errors.Forbidden as e:
            logger.error(f"403 on reply to {tweet_id}: {e}")
            return None

    # Truncate gracefully
    truncated = text[: char_limit - 10]
    for punct in (". ", "! ", "? "):
        idx = truncated.rfind(punct)
        if idx > char_limit * 0.7:
            truncated = text[: idx + 1]
            break
    else:
        truncated = text[: char_limit - 3] + "…"

    try:
        resp = client.create_tweet(text=truncated, in_reply_to_tweet_id=tweet_id)
        logger.info(f"Replied (truncated) to {tweet_id} → {resp.data['id']}")
        return resp
    except tweepy.errors.Forbidden as e:
        logger.error(f"403 on truncated reply to {tweet_id}: {e}")
        return None


def get_tweet_by_id(client: tweepy.Client, tweet_id: int):
    return client.get_tweet(
        tweet_id,
        tweet_fields=_TWEET_FIELDS,
        expansions=_EXPANSIONS,
        media_fields=_MEDIA_FIELDS,
        user_fields=["username", "name"],
    )


class TweetCache:
    """Memoize get_tweet_by_id for the process lifetime.

    Parent/root/quoted tweets are immutable, so the bot needn't re-fetch the
    same tweet on every reply in a thread. Bounded (oldest evicted first) so it
    can't grow without limit. Only successful lookups are cached; None results
    (errors/missing) are left uncached so they get another chance later.
    """

    def __init__(self, client: tweepy.Client, max_size: int = None):
        self._client = client
        self._cache: dict = {}
        self._max = max_size or Config.TWEET_CACHE_SIZE
        self.hits = 0
        self.misses = 0

    def get(self, tweet_id):
        key = str(tweet_id)
        if key in self._cache:
            self.hits += 1
            return self._cache[key]

        self.misses += 1
        resp = get_tweet_by_id(self._client, tweet_id)
        if resp is not None:
            self._cache[key] = resp
            if len(self._cache) > self._max:
                self._cache.pop(next(iter(self._cache)))
        return resp
