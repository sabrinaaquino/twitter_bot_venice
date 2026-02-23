#!/usr/bin/env python3
"""
Manual reply tool — test the pipeline on a specific tweet.
Usage: python reply_to_tweet.py <tweet_url_or_id>
"""
import sys
import os
import re
import requests
from typing import List, Optional, Tuple

import tweepy

# Ensure imports work from any directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from clients import get_twitter_client
from twitter_client import get_tweet_by_id, reply_to_tweet
from venice_api import analyse, craft_tweet
from image_processor import process_tweet_media
from utils import extract_urls_from_entities, extract_urls_from_text
from safety import screen_urls, classify_url


def extract_tweet_id(url: str) -> Optional[str]:
    m = re.search(r"/status/(\d+)", url)
    if m:
        return m.group(1)
    return url if url.isdigit() else None


def fetch_context(client, tweet) -> Tuple[Optional[str], List[str], Optional[bytes], Optional[str]]:
    """Get conversation context, URLs, and parent image if any."""
    ctx_text = None
    urls: List[str] = []
    img_bytes = None
    img_url = None

    if hasattr(tweet, "conversation_id") and tweet.conversation_id != tweet.id:
        print("🔍 Part of a conversation — fetching parent …")
        try:
            parent = get_tweet_by_id(client, tweet.conversation_id)
            if parent and parent.data:
                ctx_text = parent.data.text
                print(f"📋 Context: {ctx_text[:120]}…")
                urls.extend(extract_urls_from_entities(getattr(parent.data, "entities", None)))
                urls.extend(extract_urls_from_text(ctx_text))

                # Parent images
                att = getattr(parent.data, "attachments", None)
                if att and parent.includes and "media" in parent.includes:
                    lookup = {m.media_key: m for m in parent.includes["media"]}
                    for key in att.get("media_keys", []):
                        media = lookup.get(key)
                        if media and media.type == "photo" and getattr(media, "url", None):
                            try:
                                r = requests.get(media.url, timeout=10)
                                if r.ok:
                                    img_bytes = r.content
                                    img_url = media.url
                                    print(f"🖼️ Parent image: {len(img_bytes)} bytes")
                                    break
                            except Exception:
                                pass
        except Exception as e:
            print(f"⚠️ Could not fetch parent: {e}")
    else:
        print("📝 Standalone tweet")

    urls.extend(extract_urls_from_entities(getattr(tweet, "entities", None)))
    urls.extend(extract_urls_from_text(tweet.text))
    return ctx_text, list(dict.fromkeys(urls)), img_bytes, img_url


def main():
    if len(sys.argv) != 2:
        print("Usage: python reply_to_tweet.py <tweet_url_or_id>")
        sys.exit(1)

    tweet_id = extract_tweet_id(sys.argv[1])
    if not tweet_id:
        print("❌ Bad input — need a tweet URL or numeric ID")
        sys.exit(1)

    print(f"🐦 Tweet ID: {tweet_id}")

    client = get_twitter_client()
    print("✅ Twitter connected")

    resp = get_tweet_by_id(client, tweet_id)
    if not resp or not resp.data:
        print("❌ Tweet not found")
        sys.exit(1)

    tweet = resp.data
    print(f"📝 {tweet.text[:140]}…")

    ctx_text, urls, ctx_img, ctx_img_url = fetch_context(client, tweet)

    # Direct media
    media_lookup = {}
    if resp.includes and "media" in resp.includes:
        media_lookup = {m.media_key: m for m in resp.includes["media"]}
    img_bytes, img_url = process_tweet_media(tweet, media_lookup)

    if not img_bytes and ctx_img:
        img_bytes, img_url = ctx_img, ctx_img_url
        print("🖼️ Using parent image")

    # URL safety screening
    safe, suspicious, blocked = screen_urls(urls)
    if safe:
        print(f"✅ Trusted URLs: {', '.join(safe)}")
    if suspicious:
        print(f"⚠️ Suspicious URLs: {', '.join(suspicious)}")
    if blocked:
        print(f"🚫 Blocked scam URLs: {', '.join(blocked)}")
    for u in urls:
        print(f"   {classify_url(u):>10} │ {u}")

    # Generate
    print("🤖 Analysing …")
    analysis = analyse(
        tweet.text, context=ctx_text, image_bytes=img_bytes, image_url=img_url, urls=urls
    )
    print("✍️ Crafting tweet …")
    final = craft_tweet(analysis, use_vision=bool(img_bytes or img_url), context_urls=urls)

    print(f"\n{'=' * 60}")
    print(f"🎯 RESPONSE ({len(final)} chars):")
    print("=" * 60)
    print(final)
    print("=" * 60)

    while True:
        choice = input("\nPost this reply? (y/n/edit): ").lower().strip()
        if choice in ("y", "yes"):
            try:
                r = reply_to_tweet(client, tweet_id, final)
                if r:
                    print(f"✅ Posted! https://x.com/venice_mind/status/{r.data['id']}")
                else:
                    print("❌ Post failed")
            except Exception as e:
                print(f"❌ {e}")
            break
        elif choice in ("n", "no"):
            print("👍 Not posted.")
            break
        elif choice == "edit":
            final = input("New response: ").strip() or final
            print(f"📏 {len(final)} chars")


if __name__ == "__main__":
    main()
