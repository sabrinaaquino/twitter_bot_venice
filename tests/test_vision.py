"""Agent vision: describe_image (offline, Venice call stubbed)."""
import pytest

from config import Config
from venice_api import describe_image


def test_no_image_returns_none():
    assert describe_image() is None


def test_describes_via_primary(monkeypatch):
    monkeypatch.setattr("venice_api._call_venice", lambda *a, **k: "a photo of a cat")
    assert describe_image(image_url="https://x/y.jpg") == "a photo of a cat"
    assert describe_image(image_bytes=b"\x89PNG...") == "a photo of a cat"


def test_falls_back_to_vision_model(monkeypatch):
    def fake(model, system, content, **k):
        return None if model == Config.MODEL_PRIMARY else "fallback description"
    monkeypatch.setattr("venice_api._call_venice", fake)
    assert describe_image(image_bytes=b"x") == "fallback description"


def test_both_fail_returns_none(monkeypatch):
    monkeypatch.setattr("venice_api._call_venice", lambda *a, **k: None)
    assert describe_image(image_bytes=b"x") is None
