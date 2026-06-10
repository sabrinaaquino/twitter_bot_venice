"""Twitter API wrappers — mentions, replies, tweet lookup."""
import logging
from types import SimpleNamespace

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


def get_mentions(
    client: tweepy.Client, bot_user_id: int, *, start_time: str = None, max_results: int = None
):
    """Fetch up to `max_results` mentions, paginating as needed.

    The mentions endpoint returns at most 100 per page (minimum 5). Requesting
    only the minimum (the old behaviour) meant bursts of activity left mentions
    unseen. This walks the pages until the cap is reached or there are no more,
    merging each page's tweets and de-duplicating the included media/users.

    Returns an object with `.data` (list) and `.includes` (dict), matching how
    the bot consumes a single-page response.
    """
    max_total = max_results or Config.MAX_MENTIONS_PER_CHECK

    data = []
    media, users = [], []
    seen_media, seen_users = set(), set()
    token = None

    while len(data) < max_total:
        page_size = min(100, max(5, max_total - len(data)))
        kwargs = {
            "id": bot_user_id,
            "max_results": page_size,
            "tweet_fields": _TWEET_FIELDS,
            "expansions": _EXPANSIONS,
            "media_fields": _MEDIA_FIELDS,
            "user_fields": _USER_FIELDS,
        }
        if start_time:
            kwargs["start_time"] = start_time
        if token:
            kwargs["pagination_token"] = token

        resp = client.get_users_mentions(**kwargs)
        if not resp or not resp.data:
            break

        data.extend(resp.data)

        includes = resp.includes or {}
        for m in includes.get("media", []):
            if m.media_key not in seen_media:
                seen_media.add(m.media_key)
                media.append(m)
        for u in includes.get("users", []):
            if u.id not in seen_users:
                seen_users.add(u.id)
                users.append(u)

        token = (resp.meta or {}).get("next_token")
        if not token:
            break

    return SimpleNamespace(data=data[:max_total], includes={"media": media, "users": users})


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
