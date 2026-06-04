"""Authoritative Venice knowledge: FAQ snapshot + live model list.

FAQ answers are served from a committed snapshot (venice_faqs.json), refreshed
by scripts/fetch_venice_data.py. Model data is fetched live from the Venice API
with a 6h in-process TTL cache, falling back to the committed venice_models.json
snapshot on any failure.

Security/domain rules and the curated essentials baseline live in
config.ANALYST_PROMPT (always present, even if a snapshot is missing).
"""
import json
import logging
import os
import re
import time

import requests

from config import Config

logger = logging.getLogger(__name__)
_DIR = os.path.dirname(os.path.abspath(__file__))

# ── FAQ (snapshot) ───────────────────────────────────────────
_faqs_cache = None  # list[{"id","title","markdown","category"}]


def _load_faqs():
    global _faqs_cache
    if _faqs_cache is not None:
        return _faqs_cache
    items = []
    try:
        with open(os.path.join(_DIR, Config.VENICE_FAQ_FILE), encoding="utf-8") as f:
            data = json.load(f)
        for c in data["locales"]["en"]["categories"]:
            for q in c.get("questions", []):
                items.append({
                    "id": q.get("id", ""),
                    "title": q.get("title", ""),
                    "markdown": q.get("markdown", ""),
                    "category": c.get("title", ""),
                })
    except Exception as e:
        logger.warning(f"FAQ snapshot unavailable ({e}); relying on prompt baseline + web search")
    _faqs_cache = items
    return items


def relevant_faqs(query, context=None, limit=4):
    """Return up to `limit` 'Q/A' strings most relevant to the query."""
    text = f"{query} {context or ''}".lower()
    words = {w for w in re.findall(r"[a-z0-9]+", text) if len(w) > 2}
    scored = []
    for item in _load_faqs():
        title_words = set(re.findall(r"[a-z0-9]+", item["title"].lower()))
        body = item["markdown"].lower()
        score = 3 * len(words & title_words) + sum(1 for w in words if w in body)
        if score > 0:
            scored.append((score, item))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [f"Q: {it['title']}\nA: {it['markdown']}" for _, it in scored[:limit]]


# ── Models (live API, 6h TTL, snapshot fallback) ─────────────
_models_cache = {"data": None, "ts": 0.0}


def _load_models_snapshot():
    try:
        with open(os.path.join(_DIR, Config.VENICE_MODELS_FILE), encoding="utf-8") as f:
            return json.load(f).get("data", [])
    except Exception as e:
        logger.warning(f"Models snapshot unavailable ({e})")
        return []


def get_models(type=None):
    """Live model list with a 6h TTL cache; falls back to the committed snapshot.

    Pass `type` (e.g. "text", "image", "video") to filter; None returns all.
    """
    now = time.time()
    fresh = _models_cache["data"] is not None and (
        now - _models_cache["ts"] <= Config.VENICE_MODELS_TTL_SECONDS
    )
    if not fresh:
        try:
            r = requests.get(
                Config.VENICE_MODELS_URL + "?type=all",
                headers={"Authorization": f"Bearer {Config.VENICE_API_KEY}"},
                timeout=15,
            )
            r.raise_for_status()
            data = r.json().get("data", [])
            if not data:
                raise ValueError("empty model list")
        except Exception as e:
            logger.warning(f"Live models fetch failed ({e}); using snapshot")
            data = _load_models_snapshot()
        _models_cache["data"] = data
        _models_cache["ts"] = now  # cache even failures to avoid hammering

    data = _models_cache["data"] or []
    if type:
        data = [m for m in data if m.get("type") == type]
    return data


def summarize_models(models, limit=30):
    """One compact line per model: name (id) - ctx - capabilities - price - type."""
    lines = []
    for m in models[:limit]:
        spec = m.get("model_spec", {})
        caps = spec.get("capabilities", {})
        pricing = spec.get("pricing", {})
        ctx = m.get("context_length") or spec.get("availableContextTokens") or 0
        flags = [
            name for key, name in (
                ("supportsVision", "vision"),
                ("supportsReasoning", "reasoning"),
                ("supportsFunctionCalling", "functions"),
                ("supportsWebSearch", "web"),
            ) if caps.get(key)
        ]
        in_usd = pricing.get("input", {}).get("usd")
        out_usd = pricing.get("output", {}).get("usd")
        price = f"${in_usd}/${out_usd} per 1M tok" if in_usd is not None else "price n/a"
        # FUTURE TODO: once Venice model landing pages are live, append each model's
        # landing-page URL here and update ANALYST_PROMPT to instruct the bot to link
        # that page in any response that names a specific model.
        lines.append(
            f"- {spec.get('name') or m.get('id')} ({m.get('id')}) - "
            f"{ctx // 1000}K ctx - {', '.join(flags) or 'text'} - {price} - type={m.get('type')}"
        )
    return "\n".join(lines)
