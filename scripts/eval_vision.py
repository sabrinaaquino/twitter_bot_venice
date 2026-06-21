#!/usr/bin/env python3
"""Live probe of agent vision (describe_image) — NOT a pytest test.

Hits the real Venice vision model, so it costs tokens / credits. It is a plain
script (no `test_` prefix, lives in scripts/) so pytest never collects it — run
it ON DEMAND to eyeball what the model "sees" for a given image:

    python scripts/eval_vision.py https://example.com/cat.jpg
    python scripts/eval_vision.py ./local/photo.png            # local file → bytes
    python scripts/eval_vision.py <url> --model qwen3-vl-235b-a22b   # probe one model
    python scripts/eval_vision.py                              # built-in sample URLs

By default it calls the production `venice_api.describe_image` — the exact
function the agent uses — so what you see is what the bot would fold into the
ReAct context as `[IMAGE the user shared]: …`. With `--model` it bypasses the
primary→fallback cascade and asks one specific model directly (to A/B vision
models). The offline test in `tests/test_vision.py` stubs the call; THIS hits
the network.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config
from venice_api import describe_image, _call_venice, _DESCRIBE_SYSTEM

# A couple of stable, public sample images to use when no source is given.
DEFAULT_SAMPLES = [
    "https://upload.wikimedia.org/wikipedia/commons/3/3a/Cat03.jpg",
    "https://upload.wikimedia.org/wikipedia/commons/d/d9/Collage_of_Nine_Dogs.jpg",
]


def _load(source: str):
    """Return (image_bytes, image_url): URL passes through; a local path is read as bytes."""
    if source.startswith(("http://", "https://")):
        return None, source
    with open(source, "rb") as f:
        return f.read(), None


def _describe_with_model(model: str, image_bytes, image_url):
    """Single-model probe (bypasses the cascade) — mirrors describe_image's payload."""
    if image_url:
        img_part = {"type": "image_url", "image_url": {"url": image_url}}
    else:
        import base64
        b64 = base64.b64encode(image_bytes).decode()
        img_part = {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{b64}"}}
    content = [{"type": "text", "text": "Describe this image for a tweet reply."}, img_part]
    return _call_venice(model, _DESCRIBE_SYSTEM, content)


def main() -> int:
    parser = argparse.ArgumentParser(description="Live probe of agent vision (describe_image).")
    parser.add_argument("sources", nargs="*", help="image URL(s) or local file path(s)")
    parser.add_argument("--model", help="probe one specific model instead of the prod cascade")
    args = parser.parse_args()

    if not Config.VENICE_API_KEY:
        print("VENICE_API_KEY not set — this is a LIVE probe that needs it.")
        return 2

    sources = args.sources or DEFAULT_SAMPLES
    mode = f"model={args.model}" if args.model else f"cascade ({Config.MODEL_PRIMARY} → {Config.MODEL_VISION_FALLBACK})"
    print(f"Vision probe — {mode}\n")

    failures = 0
    for src in sources:
        print(src)
        print("-" * min(len(src), 74))
        try:
            image_bytes, image_url = _load(src)
        except OSError as e:
            print(f"  [ERROR] could not read source: {e}\n")
            failures += 1
            continue
        if args.model:
            desc = _describe_with_model(args.model, image_bytes, image_url)
        else:
            desc = describe_image(image_bytes=image_bytes, image_url=image_url)
        if desc:
            print(f"  → {desc}\n")
        else:
            print("  [no description — model returned nothing / unavailable]\n")
            failures += 1

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
