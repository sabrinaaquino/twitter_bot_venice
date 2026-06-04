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
