"""Routing/detection helpers in venice_api (pure, offline)."""
import pytest

from venice_api import _needs_fresh_data, _is_venice_topic, _is_model_question


@pytest.mark.parametrize(
    "query, expected",
    [
        ("What is the current price of VVV?", True),
        ("What's the latest news about Venice AI?", True),
        ("How much is Bitcoin worth today?", True),
        ("What models does Venice have?", True),
        ("What is the TVL of VVV staking?", True),
        ("Tell me about the Diem system", True),
        ("Who won the election?", True),
        ("What's the weather like?", True),
        ("What is 2 + 2?", False),
        ("Explain quantum physics", False),
        ("Write me a poem about cats", False),
        ("How do I make pasta?", False),
    ],
)
def test_needs_fresh_data(query, expected):
    assert _needs_fresh_data(query) is expected


@pytest.mark.parametrize(
    "query, expected",
    [
        ("What is DIEM?", True),
        ("How does VVV staking work?", True),
        ("How do I make pasta?", False),
    ],
)
def test_is_venice_topic(query, expected):
    assert _is_venice_topic(query) is expected


@pytest.mark.parametrize(
    "query, expected",
    [
        ("Which Venice model has the biggest context window?", True),
        ("Does Venice have a vision model?", True),
        ("What is 2 + 2?", False),
    ],
)
def test_is_model_question(query, expected):
    assert _is_model_question(query) is expected
