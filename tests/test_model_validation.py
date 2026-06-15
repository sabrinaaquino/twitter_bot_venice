"""Plan 0001 — detect & alert on unavailable Venice models.

These tests are written test-first. They cover:
- pure detection of configured models missing from an available set
- the startup validator's logging behaviour (loud for a missing primary)
- not crying wolf when the available list can't be determined
- HTTP error classification so 402/401/404 are distinguishable in logs
"""
import logging

import pytest

from config import Config
import venice_knowledge as vk
from venice_api import _http_error_hint


# ── Pure detection ────────────────────────────────────────────────

def test_missing_configured_models_flags_absent_ids():
    # primary present, last-resort absent
    available = [
        Config.MODEL_PRIMARY,
        Config.MODEL_UNCENSORED,
        Config.MODEL_VISION_FALLBACK,
        "some-other-model",
    ]
    missing = vk.missing_configured_models(available)
    assert missing == {"MODEL_LAST_RESORT": Config.MODEL_LAST_RESORT}


def test_missing_configured_models_empty_when_all_present():
    available = [
        Config.MODEL_PRIMARY,
        Config.MODEL_UNCENSORED,
        Config.MODEL_VISION_FALLBACK,
        Config.MODEL_LAST_RESORT,
    ]
    assert vk.missing_configured_models(available) == {}


# ── Startup validator ─────────────────────────────────────────────

def test_validate_logs_critical_when_primary_missing(monkeypatch, caplog):
    # Available list lacks the primary model.
    monkeypatch.setattr(
        vk, "get_models",
        lambda: [{"id": Config.MODEL_UNCENSORED},
                 {"id": Config.MODEL_VISION_FALLBACK},
                 {"id": Config.MODEL_LAST_RESORT}],
    )
    with caplog.at_level(logging.CRITICAL, logger="venice_knowledge"):
        missing = vk.validate_configured_models()

    assert "MODEL_PRIMARY" in missing
    assert any(r.levelno >= logging.CRITICAL for r in caplog.records)
    assert any(Config.MODEL_PRIMARY in r.getMessage() for r in caplog.records)


def test_validate_returns_empty_when_all_present(monkeypatch):
    monkeypatch.setattr(
        vk, "get_models",
        lambda: [{"id": Config.MODEL_PRIMARY},
                 {"id": Config.MODEL_UNCENSORED},
                 {"id": Config.MODEL_VISION_FALLBACK},
                 {"id": Config.MODEL_LAST_RESORT}],
    )
    assert vk.validate_configured_models() == {}


def test_validate_skips_when_model_list_undetermined(monkeypatch, caplog):
    # Empty available list → can't tell; must NOT report everything missing.
    monkeypatch.setattr(vk, "get_models", lambda: [])
    with caplog.at_level(logging.WARNING, logger="venice_knowledge"):
        missing = vk.validate_configured_models()
    assert missing == {}
    assert any("skipping" in r.getMessage().lower() for r in caplog.records)


# ── HTTP error classification (part 2) ────────────────────────────

@pytest.mark.parametrize(
    "status, needle",
    [
        (401, "auth"),
        (402, "payment"),
        (404, "not found"),
        (429, "rate"),
    ],
)
def test_http_error_hint_known_codes(status, needle):
    hint = _http_error_hint(status)
    assert hint and needle in hint.lower()


def test_http_error_hint_unknown_code_is_none():
    assert _http_error_hint(500) is None
