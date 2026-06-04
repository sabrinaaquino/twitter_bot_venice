#!/usr/bin/env python3
"""Refresh local snapshots of Venice's FAQ and model list.

Run manually or via cron:
    python scripts/fetch_venice_data.py

Writes venice_faqs.json and venice_models.json to the repo root. On failure
for a given source, logs to stderr and leaves the existing file untouched
(exits non-zero so cron can alert).
"""
import json
import os
import sys

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FAQ_URL = "https://venice.ai/api/faqs"
MODELS_URL = "https://api.venice.ai/api/v1/models?type=all"


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


def _write_if_valid(filename, data, validate):
    if not validate(data):
        raise ValueError(f"validation failed for {filename}")
    path = os.path.join(ROOT, filename)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
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
        _write_if_valid("venice_models.json", _fetch_json(MODELS_URL, headers), _valid_models)
        print("OK: venice_models.json updated")
    except Exception as e:
        print(f"ERROR: models fetch failed ({e}); keeping existing file", file=sys.stderr)
        ok = False

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
