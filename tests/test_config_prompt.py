"""ANALYST_PROMPT must not carry stale/volatile Venice facts.

The bot defers Venice token mechanics and model specs to authoritative facts +
web search, so the prompt must not bake in claims that drift or are wrong.
"""
import pytest

from config import Config

# Strings that must NOT appear — they are stale, wrong, or volatile.
BANNED = [
    "non-transferable",            # DIEM IS transferable
    "earn Diem daily",             # DIEM is minted, not earned daily
    "Total supply: inflationary",  # volatile tokenomics dump
    "GLM 4.6: default model",      # hardcoded model list (drifts)
    "Kimi K2.5: trillion-param",   # hardcoded model spec (drifts)
]

# Strings that MUST appear — accurate baseline + defer-to-truth behaviour.
REQUIRED = [
    "trust",  # defers to authoritative facts/search
    "DIEM",   # accurate essentials baseline present
]


@pytest.mark.parametrize("banned", BANNED)
def test_prompt_omits_stale_facts(banned):
    assert banned not in Config.ANALYST_PROMPT


@pytest.mark.parametrize("required", REQUIRED)
def test_prompt_keeps_required_anchors(required):
    assert required.lower() in Config.ANALYST_PROMPT.lower()
