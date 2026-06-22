"""Finding D — cache thread-context tweet lookups.

Parent / conversation-root / quoted tweets are immutable, but _extract_context
re-fetches them from the Twitter API on every reply. TweetCache memoizes
get_tweet_by_id for the process lifetime (bounded, oldest evicted first), so
repeated lookups of the same tweet across a thread cost one API call, not N.
"""
import pytest

from twitter_client import TweetCache


class FakeResp:
    def __init__(self, tweet_id):
        self.data = type("D", (), {"id": tweet_id, "text": f"tweet {tweet_id}"})()


class FakeClient:
    """Counts get_tweet calls; returns a FakeResp (or None for configured ids)."""
    def __init__(self, none_ids=()):
        self.calls = 0
        self._none_ids = set(str(i) for i in none_ids)

    def get_tweet(self, tweet_id, **kwargs):
        self.calls += 1
        if str(tweet_id) in self._none_ids:
            return None
        return FakeResp(tweet_id)


def test_repeated_lookup_hits_api_once():
    client = FakeClient()
    cache = TweetCache(client)
    a = cache.get("100")
    b = cache.get("100")
    assert client.calls == 1
    assert a is b
    assert cache.hits == 1 and cache.misses == 1


def test_distinct_ids_each_fetch_once():
    client = FakeClient()
    cache = TweetCache(client)
    cache.get("1")
    cache.get("2")
    cache.get("1")
    assert client.calls == 2  # "1" served from cache the second time


def test_none_results_are_not_cached():
    client = FakeClient(none_ids=["404"])
    cache = TweetCache(client)
    assert cache.get("404") is None
    assert cache.get("404") is None
    assert client.calls == 2  # not cached -> re-fetched


def test_cache_is_bounded_evicting_oldest():
    client = FakeClient()
    cache = TweetCache(client, max_size=2)
    cache.get("1")
    cache.get("2")
    cache.get("3")          # evicts "1"
    assert "1" not in cache._cache
    cache.get("1")          # must re-fetch
    assert client.calls == 4
