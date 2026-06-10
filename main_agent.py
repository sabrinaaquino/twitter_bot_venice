#!/usr/bin/env python3
"""CLI harness for the ReAct agent slice (Milestone 1).

Runs ONE query or tweet through the reply pipeline and PRINTS the result. It does
not poll for mentions and does not auto-post (unless --post). Routes through the
ReAct agent when Config.USE_AGENT, else the legacy analyse()/craft_tweet() path —
so you can compare the two on the same input.

    USE_AGENT=false python main_agent.py --query "What is DIEM?"      # legacy
    USE_AGENT=true  python main_agent.py --query "What is DIEM?"      # agent
    USE_AGENT=true  python main_agent.py https://x.com/u/status/123    # real tweet

Live model/embedding calls currently fail with HTTP 402 (no Venice credits); the
harness still exercises the wiring and the safety guardrail end-to-end.
"""
import argparse
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import Config

logger = logging.getLogger("main_agent")


def reply_for(query, *, context=None, urls=None, image_bytes=None, image_url=None):
    """Produce a reply for one input via the active pipeline."""
    urls = urls or []
    if Config.USE_AGENT:
        from agent.guardrails import agent_reply
        res = agent_reply(query, context=context, urls=urls)
        if res.text is None:
            return "(no engagement — user blocked / silent)"
        return res.text
    # Legacy pipeline
    from venice_api import analyse, craft_tweet
    analysis = analyse(query, context=context, urls=urls,
                       image_bytes=image_bytes, image_url=image_url)
    return craft_tweet(analysis, context_urls=urls)


def _run_on_tweet(tweet_ref, post=False):
    Config.validate()
    from clients import get_twitter_client
    from twitter_client import get_tweet_by_id, reply_to_tweet
    from reply_to_tweet import extract_tweet_id, fetch_context

    tweet_id = extract_tweet_id(tweet_ref)
    if not tweet_id:
        raise SystemExit(f"Could not parse a tweet id from {tweet_ref!r}")

    client = get_twitter_client()
    resp = get_tweet_by_id(client, tweet_id)
    if not (resp and resp.data):
        raise SystemExit(f"Tweet {tweet_id} not found")
    tweet = resp.data

    ctx_text, urls, img_bytes, img_url = fetch_context(client, tweet)
    query = tweet.text.replace("@venice_mind", "").replace("@venice_bot", "").strip()
    reply = reply_for(query, context=ctx_text, urls=urls,
                      image_bytes=img_bytes, image_url=img_url)

    if post and reply:
        reply_to_tweet(client, tweet_id, reply)
        print("Posted.")
    return reply


def main():
    logging.basicConfig(level=getattr(logging, Config.LOG_LEVEL), format=Config.LOG_FORMAT)
    p = argparse.ArgumentParser(description="Agent-slice CLI harness")
    p.add_argument("tweet", nargs="?", help="tweet URL or numeric id")
    p.add_argument("--query", help="run on this text directly (no Twitter)")
    p.add_argument("--post", action="store_true", help="actually post the reply to the tweet")
    args = p.parse_args()

    mode = "AGENT" if Config.USE_AGENT else "LEGACY"
    if args.query:
        print(f"[{mode}] query: {args.query!r}")
        reply = reply_for(args.query)
    elif args.tweet:
        print(f"[{mode}] tweet: {args.tweet}")
        reply = _run_on_tweet(args.tweet, post=args.post)
    else:
        p.error("provide a tweet URL/id or --query")

    print("\n--- REPLY ---")
    print(reply)


if __name__ == "__main__":
    main()
