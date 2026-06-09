"""Live Venice API tests.

Excluded from the default run (see pytest.ini `addopts = -m "not live"`).
Run explicitly with:  pytest -m live
Also auto-skipped if VENICE_API_KEY is not configured.
"""
import pytest

from config import Config
from safety import screen_urls
from venice_api import analyse, craft_tweet

# Every test in this module is a live test and needs a key.
pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not Config.VENICE_API_KEY, reason="VENICE_API_KEY not set"),
]


@pytest.mark.parametrize(
    "query, context, urls",
    [
        ("What is 2 + 2?", None, None),
        ("What is Venice AI?", None, None),
        ("Is this site legit?", None, ["https://vvvevent.com/claim"]),
    ],
)
def test_analyse_and_craft_return_usable_replies(query, context, urls):
    result = analyse(query, context=context, urls=urls)
    assert result and result != Config.ERROR_MESSAGE

    final = craft_tweet(result, context_urls=urls)
    assert final and final != Config.ERROR_MESSAGE
    assert len(final) <= Config.char_limit()


def test_scam_url_is_blocked_and_warned():
    query = "Is this Venice AI event legit? Should I connect my wallet?"
    urls = ["https://vvvevent.com/claim"]

    safe, suspicious, blocked = screen_urls(urls)
    assert blocked, "scam URL should be blocked before AI processing"

    result = analyse(query, urls=urls)
    assert any(kw in result.lower() for kw in ("scam", "phishing", "not affiliated"))
