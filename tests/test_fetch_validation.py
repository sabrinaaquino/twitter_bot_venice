"""Refresh-script payload validators accept good data, reject bad."""
import pytest

from scripts.fetch_venice_data import _valid_faqs, _valid_models


@pytest.mark.parametrize(
    "validator, payload, expected",
    [
        (_valid_faqs, {"locales": {"en": {"categories": []}}}, True),
        (_valid_faqs, {"nope": 1}, False),
        (_valid_faqs, "not a dict", False),
        (_valid_models, {"data": [{"id": "x"}]}, True),
        (_valid_models, {"data": []}, False),
        (_valid_models, {"data": "x"}, False),
    ],
)
def test_payload_validators(validator, payload, expected):
    assert bool(validator(payload)) is expected
