#!/usr/bin/env python3
"""Refresh local snapshots of Venice's FAQ and model list.

Run manually or via cron:
    python scripts/fetch_venice_data.py

Writes venice_faqs.json and venice_models.json to the repo root. On failure
for a given source, logs to stderr and leaves the existing file untouched
(exits non-zero so cron can alert).

The models snapshot is slimmed to the fields the bot actually reads and written
one model per line (sorted by id), keeping the committed file small and its diffs
reviewable. The live Venice models API stays the primary source at runtime.
"""
import json
import os
import sys

import requests

try:
    from dotenv import load_dotenv
except ImportError:  # dotenv is a project dep; degrade gracefully if absent
    load_dotenv = None

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if load_dotenv:
    load_dotenv(os.path.join(ROOT, ".env"))  # pick up VENICE_API_KEY when present
FAQ_URL = "https://venice.ai/api/faqs"
MODELS_URL = "https://api.venice.ai/api/v1/models?type=all"

# Only these model fields are consumed by venice_knowledge (get_models / summarize_models).
_CAP_KEYS = ("supportsVision", "supportsReasoning", "supportsFunctionCalling", "supportsWebSearch")


def _fetch_json(url, headers=None):
    r = requests.get(url, headers=headers or {}, timeout=30)
    r.raise_for_status()
    return r.json()


def _valid_faqs(d):
    return (
        isinstance(d, dict)
        and isinstance(d.get("locales"), dict)
        and "en" in d["locales"]
    )


def _valid_models(d):
    return isinstance(d, dict) and isinstance(d.get("data"), list) and len(d["data"]) > 0


def _slim_model(m):
    """Keep only the fields the bot reads, preserving the live API's nested shape."""
    spec = m.get("model_spec") or {}
    caps = spec.get("capabilities") or {}
    pricing = spec.get("pricing") or {}
    return {
        "id": m.get("id"),
        "type": m.get("type"),
        "context_length": m.get("context_length"),
        "model_spec": {
            "name": spec.get("name"),
            "availableContextTokens": spec.get("availableContextTokens"),
            "capabilities": {k: caps.get(k) for k in _CAP_KEYS},
            "pricing": {
                "input": {"usd": (pricing.get("input") or {}).get("usd")},
                "output": {"usd": (pricing.get("output") or {}).get("usd")},
            },
        },
    }


def _slim_models_payload(raw):
    """Slim every model and sort by id so future refreshes produce minimal diffs."""
    models = sorted(
        (_slim_model(m) for m in raw.get("data", [])),
        key=lambda m: m.get("id") or "",
    )
    return {"object": raw.get("object", "list"), "type": raw.get("type", "all"), "data": models}


def _dump_models_str(payload):
    """Serialize with one model per line (compact per-model) for small, reviewable diffs."""
    model_lines = ",\n".join(
        "    " + json.dumps(m, ensure_ascii=False, separators=(",", ":"))
        for m in payload.get("data", [])
    )
    return (
        "{\n"
        f'  "object": {json.dumps(payload.get("object", "list"))},\n'
        f'  "type": {json.dumps(payload.get("type", "all"))},\n'
        '  "data": [\n'
        f"{model_lines}\n"
        "  ]\n"
        "}\n"
    )


def _write_if_valid(filename, data, validate, serialize=None):
    if not validate(data):
        raise ValueError(f"validation failed for {filename}")
    text = serialize(data) if serialize else json.dumps(data, ensure_ascii=False, indent=2)
    path = os.path.join(ROOT, filename)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def main():
    api_key = os.getenv("VENICE_API_KEY")
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    ok = True

    try:
        _write_if_valid("venice_faqs.json", _fetch_json(FAQ_URL), _valid_faqs)
        print("OK: venice_faqs.json updated")
    except Exception as e:
        print(f"ERROR: FAQ fetch failed ({e}); keeping existing file", file=sys.stderr)
        ok = False

    try:
        slim = _slim_models_payload(_fetch_json(MODELS_URL, headers))
        _write_if_valid("venice_models.json", slim, _valid_models, serialize=_dump_models_str)
        print(f"OK: venice_models.json updated ({len(slim['data'])} models, slimmed)")
    except Exception as e:
        print(f"ERROR: models fetch failed ({e}); keeping existing file", file=sys.stderr)
        ok = False

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
