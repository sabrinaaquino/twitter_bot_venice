"""LLM security / spam gate (a PRE layer for the agent path).

A *semantic* complement to the deterministic `agent.safety` screens: a small model
judges whether a mention is worth engaging (RESPOND) or is spam / a scam / a
transaction-command trick (STOP). It catches the NOVEL tricks the regex patterns
can't anticipate — the point of adding it.

Wiring (in agent.guardrails): runs AFTER the deterministic screens (cheap-first —
only on inputs that already passed the blocklist + injection + URL checks), and
only when `Config.LLM_SECURITY_FILTER` is on. It tries the small classifier model
first and **falls back to the primary agent model** if that fails, so the gate
keeps working even when the small model is down. **Fail-open** only if EVERY model
fails (→ RESPOND): the deterministic screens already passed and remain the safety
floor (a Venice hiccup must not silence the bot). A STOP is treated by the caller
as a spam offense → warn-once-then-block via state.py.
"""
import json
import logging
import re
from typing import Optional

from config import Config

logger = logging.getLogger(__name__)


def _build_user_content(query: str, context: Optional[str]) -> str:
    parts = []
    if context:
        parts.append(f"Thread / context:\n{context}")
    parts.append(f"Current message:\n{query}")
    return "\n\n".join(parts)


def _verdict_from_json(text: str):
    """Parse {"verdict": "..."} from the model output (tolerating ```json fences).
    Returns "STOP" | "RESPOND" | None (not parseable as our JSON)."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z]*\s*|\s*```$", "", cleaned).strip()
    try:
        obj = json.loads(cleaned)
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None
    v = str(obj.get("verdict", "")).strip().upper()
    return v if v in ("STOP", "RESPOND") else None


def _verdict_from_text(text: str):
    """Fallback for models that ignore JSON mode: scan the raw text.
    Returns "STOP" | "RESPOND" | None."""
    u = text.strip().upper()
    if u.startswith("STOP"):
        return "STOP"
    if u.startswith("RESPOND"):
        return "RESPOND"
    if "STOP" in u and "RESPOND" not in u:
        return "STOP"
    if "RESPOND" in u and "STOP" not in u:
        return "RESPOND"
    return None


def llm_should_respond(query: str, context: Optional[str] = None, *, model: str = None) -> bool:
    """True = RESPOND (engage), False = STOP (block).

    Tries the small classifier model first, then **falls back to the primary
    agent model** (Config.AGENT_MODEL) if it errors / returns nothing / gives no
    clear verdict — so the gate keeps working even if the small model is down or
    not enabled on the account. Only if EVERY model fails do we fail open
    (RESPOND): the deterministic screens already passed and remain the floor.

    Asks for a JSON verdict ({"verdict": ...}); falls back to a raw-text scan if a
    model ignores JSON mode.
    """
    from venice_api import _call_venice

    # Ordered, de-duplicated: requested/configured small model → primary fallback.
    candidates = []
    for m in (model or Config.SECURITY_FILTER_MODEL, Config.AGENT_MODEL):
        if m and m not in candidates:
            candidates.append(m)

    content = _build_user_content(query, context)
    for m in candidates:
        try:
            out = _call_venice(
                m, Config.SECURITY_PROMPT, content,
                temperature=0.0, response_format={"type": "json_object"},
            )
        except Exception as e:
            logger.warning("Security gate model %s errored (%s); trying fallback", m, e)
            continue
        if not out:
            logger.warning("Security gate model %s returned nothing; trying fallback", m)
            continue
        verdict = _verdict_from_json(out) or _verdict_from_text(out)
        if verdict is None:
            logger.warning("Security gate model %s gave no clear verdict (%r); trying fallback",
                           m, out[:60])
            continue
        logger.info("Security gate [%s]: %s :: %r", m, verdict, query[:40])
        return verdict != "STOP"

    logger.warning("Security gate: all models failed; failing open (RESPOND)")
    return True
