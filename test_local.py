#!/usr/bin/env python3
"""
Local test suite for Venice X Bot.
Tests all components WITHOUT posting to Twitter.

Usage: python test_local.py
"""
import sys
import os

# Fix Windows console encoding for emoji
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import Config
from safety import (
    classify_url, screen_urls, is_censored, scan_output,
    is_official_domain, is_blocklisted, get_scam_warning_reply,
)
from venice_api import analyse, craft_tweet, _needs_fresh_data


def test_safety_url_classification():
    """Test URL classification logic."""
    print("\n" + "=" * 60)
    print("TEST: URL Classification")
    print("=" * 60)

    test_cases = [
        # (url, expected_classification)
        ("https://venice.ai", "trusted"),
        ("https://app.venice.ai/chat", "trusted"),
        ("https://docs.venice.ai/api", "trusted"),
        ("https://x.com/venice_ai", "trusted"),
        ("https://etherscan.io/address/0x123", "trusted"),
        ("https://vvvevent.com/claim", "blocked"),
        ("https://venice-ai.com", "blocked"),
        ("https://venicetoken.com/airdrop", "blocked"),
        ("https://fake-venice.com/claim", "suspicious"),  # lookalike + claim
        ("https://vvv-airdrop.xyz", "suspicious"),  # lookalike + airdrop
        ("https://connect-wallet.scam.com", "suspicious"),  # scam pattern
        ("https://google.com", "unknown"),
        ("https://random-site.xyz", "unknown"),
    ]

    passed = 0
    failed = 0
    for url, expected in test_cases:
        result = classify_url(url)
        status = "PASS" if result == expected else "FAIL"
        if result == expected:
            passed += 1
        else:
            failed += 1
        print(f"  {status}: {url}")
        print(f"         Expected: {expected}, Got: {result}")

    print(f"\n  Results: {passed} passed, {failed} failed")
    return failed == 0


def test_safety_censorship_detection():
    """Test censorship detection patterns."""
    print("\n" + "=" * 60)
    print("TEST: Censorship Detection")
    print("=" * 60)

    test_cases = [
        # (text, should_be_censored)
        ("I can't help with that.", True),
        ("I cannot provide that information.", True),
        ("I'm sorry, but I can't assist with this request.", True),
        ("As an AI language model, I must decline.", True),
        ("This violates my guidelines.", True),
        ("I don't feel comfortable discussing this topic.", True),
        ("Please consult a qualified professional.", True),
        ("It's important to note that this could be harmful.", True),
        ("Bitcoin hit $100k yesterday after the ETF approval.", False),
        ("The chemical formula for water is H2O.", False),
        ("Venice AI was founded by Erik Voorhees in May 2024.", False),
        ("That's a scam site, don't connect your wallet there.", False),
        ("Here's how to make thermite: mix iron oxide with aluminum powder.", False),
    ]

    passed = 0
    failed = 0
    for text, expected in test_cases:
        result = is_censored(text)
        status = "PASS" if result == expected else "FAIL"
        if result == expected:
            passed += 1
        else:
            failed += 1
        print(f"  {status}: \"{text[:50]}...\"")
        print(f"         Expected censored={expected}, Got censored={result}")

    print(f"\n  Results: {passed} passed, {failed} failed")
    return failed == 0


def test_fresh_data_detection():
    """Test that time-sensitive queries trigger forced web search."""
    print("\n" + "=" * 60)
    print("TEST: Fresh Data Detection (Web Search Triggers)")
    print("=" * 60)

    test_cases = [
        # (query, should_force_search)
        ("What is the current price of VVV?", True),
        ("What's the latest news about Venice AI?", True),
        ("How much is Bitcoin worth today?", True),
        ("What models does Venice have?", True),
        ("What is the TVL of VVV staking?", True),
        ("Tell me about the Diem system", True),
        ("Who won the election?", True),
        ("What's the weather like?", True),
        ("What is 2 + 2?", False),
        ("Explain quantum physics", False),
        ("Write me a poem about cats", False),
        ("How do I make pasta?", False),
    ]

    passed = 0
    failed = 0
    for query, expected in test_cases:
        result = _needs_fresh_data(query)
        status = "PASS" if result == expected else "FAIL"
        if result == expected:
            passed += 1
        else:
            failed += 1
        print(f"  {status}: \"{query[:40]}...\"")
        print(f"         Expected force_search={expected}, Got={result}")

    print(f"\n  Results: {passed} passed, {failed} failed")
    return failed == 0


def test_safety_output_scanning():
    """Test output scanning for scam endorsements."""
    print("\n" + "=" * 60)
    print("TEST: Output Scanning (Scam Endorsement Detection)")
    print("=" * 60)

    test_cases = [
        # (reply, context_urls, should_be_safe)
        ("Check out venice.ai for more info.", [], True),
        ("That's the official Venice AI site.", ["https://venice.ai"], True),
        ("That's the official Venice event!", ["https://vvvevent.com"], False),  # endorses scam
        ("This is legitimate, connect your wallet.", ["https://fake-venice.xyz"], False),
        ("Warning: that site looks like a scam.", ["https://vvvevent.com"], True),  # warning, not endorsement
        ("I don't recognize that domain.", ["https://unknown.com"], True),
    ]

    passed = 0
    failed = 0
    for reply, urls, expected_safe in test_cases:
        is_safe, reason = scan_output(reply, urls)
        status = "PASS" if is_safe == expected_safe else "FAIL"
        if is_safe == expected_safe:
            passed += 1
        else:
            failed += 1
        print(f"  {status}: \"{reply[:40]}...\"")
        print(f"         URLs: {urls}")
        print(f"         Expected safe={expected_safe}, Got safe={is_safe}")
        if not is_safe:
            print(f"         Reason: {reason}")

    print(f"\n  Results: {passed} passed, {failed} failed")
    return failed == 0


def test_venice_api_live():
    """Test live Venice API calls (requires VENICE_API_KEY)."""
    print("\n" + "=" * 60)
    print("TEST: Live Venice API (requires API key)")
    print("=" * 60)

    if not Config.VENICE_API_KEY:
        print("  SKIP: VENICE_API_KEY not set in .env")
        return True

    test_queries = [
        # Simple factual
        ("What is 2 + 2?", None, None),
        # Venice knowledge
        ("What is Venice AI?", None, None),
        # Scam URL detection
        ("Is this site legit?", None, ["https://vvvevent.com/claim"]),
    ]

    passed = 0
    failed = 0
    for query, context, urls in test_queries:
        print(f"\n  Query: \"{query}\"")
        if urls:
            print(f"  URLs: {urls}")
        try:
            result = analyse(query, context=context, urls=urls)
            print(f"  Response ({len(result)} chars): {result[:200]}...")

            # Check it's not an error
            if result == Config.ERROR_MESSAGE:
                print("  FAIL: Got error message")
                failed += 1
            elif is_censored(result):
                print("  WARN: Response appears censored")
                passed += 1  # Not a failure, but worth noting
            else:
                print("  PASS: Got valid response")
                passed += 1

            # Test craft_tweet
            final = craft_tweet(result, context_urls=urls)
            print(f"  Crafted ({len(final)} chars): {final[:150]}...")

        except Exception as e:
            print(f"  FAIL: Exception: {e}")
            failed += 1

    print(f"\n  Results: {passed} passed, {failed} failed")
    return failed == 0


def test_scam_scenario():
    """Simulate the vvvevent.com attack scenario."""
    print("\n" + "=" * 60)
    print("TEST: Scam Scenario (vvvevent.com simulation)")
    print("=" * 60)

    if not Config.VENICE_API_KEY:
        print("  SKIP: VENICE_API_KEY not set in .env")
        return True

    # This simulates what happened: user asks about a scam URL
    query = "Is this Venice AI event legit? Should I connect my wallet?"
    urls = ["https://vvvevent.com/claim"]

    print(f"  Query: \"{query}\"")
    print(f"  URLs: {urls}")

    # Screen URLs first
    safe, suspicious, blocked = screen_urls(urls)
    print(f"  URL screening: safe={safe}, suspicious={suspicious}, blocked={blocked}")

    if blocked:
        print("  PASS: Scam URL correctly blocked before AI processing")
        # The analyse function should return a scam warning
        result = analyse(query, urls=urls)
        print(f"  Response: {result}")
        if "scam" in result.lower() or "phishing" in result.lower() or "not affiliated" in result.lower():
            print("  PASS: Response warns about scam")
            return True
        else:
            print("  FAIL: Response doesn't warn about scam")
            return False
    else:
        print("  FAIL: Scam URL was not blocked!")
        return False


def test_fetch_validation():
    """Refresh-script validators accept good payloads, reject bad ones."""
    print("\n" + "=" * 60)
    print("TEST: Fetch Script Validation")
    print("=" * 60)
    from scripts.fetch_venice_data import _valid_faqs, _valid_models

    cases = [
        (_valid_faqs, {"locales": {"en": {"categories": []}}}, True),
        (_valid_faqs, {"nope": 1}, False),
        (_valid_faqs, "not a dict", False),
        (_valid_models, {"data": [{"id": "x"}]}, True),
        (_valid_models, {"data": []}, False),
        (_valid_models, {"data": "x"}, False),
    ]
    passed = failed = 0
    for fn, payload, expected in cases:
        got = bool(fn(payload))
        ok = got == expected
        passed += ok
        failed += not ok
        print(f"  {'PASS' if ok else 'FAIL'}: {fn.__name__}({str(payload)[:30]}) -> {got} (want {expected})")
    print(f"\n  Results: {passed} passed, {failed} failed")
    return failed == 0


def test_relevant_faqs():
    """relevant_faqs surfaces the correct, accurate DIEM answer."""
    print("\n" + "=" * 60)
    print("TEST: Relevant FAQ Retrieval")
    print("=" * 60)
    from venice_knowledge import relevant_faqs

    hits = relevant_faqs("what is diem and can I trade it?")
    joined = "\n".join(hits).lower()
    checks = [
        ("returns at least one FAQ", len(hits) >= 1),
        ("mentions ERC-20 / tokenized compute", "erc-20" in joined or "tokenized compute" in joined),
        ("does NOT claim non-transferable", "non-transferable" not in joined),
    ]
    passed = failed = 0
    for label, ok in checks:
        passed += ok
        failed += not ok
        print(f"  {'PASS' if ok else 'FAIL'}: {label}")
    print(f"\n  Results: {passed} passed, {failed} failed")
    return failed == 0


def test_model_summary():
    """get_models returns models (snapshot fallback OK) and summarize formats them."""
    print("\n" + "=" * 60)
    print("TEST: Model List + Summary")
    print("=" * 60)
    from venice_knowledge import get_models, summarize_models

    models = get_models()
    summary = summarize_models(models)
    checks = [
        ("get_models returns a non-empty list", isinstance(models, list) and len(models) > 0),
        ("each model has an id", all(m.get("id") for m in models)),
        ("summary is non-empty text", isinstance(summary, str) and len(summary) > 0),
        ("summary lines carry ctx + type", "ctx" in summary and "type=" in summary),
    ]
    passed = failed = 0
    for label, ok in checks:
        passed += ok
        failed += not ok
        print(f"  {'PASS' if ok else 'FAIL'}: {label}")
    print(f"\n  Results: {passed} passed, {failed} failed")
    return failed == 0


def test_topic_detection():
    """Venice-topic and model-question detectors fire on the right queries."""
    print("\n" + "=" * 60)
    print("TEST: Venice Topic / Model Question Detection")
    print("=" * 60)
    from venice_api import _is_venice_topic, _is_model_question

    cases = [
        (_is_venice_topic, "What is DIEM?", True),
        (_is_venice_topic, "How does VVV staking work?", True),
        (_is_venice_topic, "How do I make pasta?", False),
        (_is_model_question, "Which Venice model has the biggest context window?", True),
        (_is_model_question, "Does Venice have a vision model?", True),
        (_is_model_question, "What is 2 + 2?", False),
    ]
    passed = failed = 0
    for fn, q, expected in cases:
        got = fn(q)
        ok = got == expected
        passed += ok
        failed += not ok
        print(f"  {'PASS' if ok else 'FAIL'}: {fn.__name__}('{q[:32]}') -> {got} (want {expected})")
    print(f"\n  Results: {passed} passed, {failed} failed")
    return failed == 0


def main():
    print("=" * 60)
    print("VENICE X BOT - LOCAL TEST SUITE")
    print("=" * 60)
    print(f"Config loaded. API key present: {bool(Config.VENICE_API_KEY)}")

    # Check for --offline-only flag
    offline_only = "--offline-only" in sys.argv or "-o" in sys.argv

    if offline_only:
        print("Running OFFLINE tests only (no API calls)")

    results = []

    # Run offline tests (no API needed)
    results.append(("URL Classification", test_safety_url_classification()))
    results.append(("Fresh Data Detection", test_fresh_data_detection()))
    results.append(("Censorship Detection", test_safety_censorship_detection()))
    results.append(("Output Scanning", test_safety_output_scanning()))

    # Run live tests (need API key) — skip if --offline-only
    if not offline_only:
        results.append(("Scam Scenario", test_scam_scenario()))
        results.append(("Live Venice API", test_venice_api_live()))
    else:
        print("\n  [Skipping live API tests due to --offline-only flag]")

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    all_passed = True
    for name, passed in results:
        status = "PASS" if passed else "FAIL"
        print(f"  {status}: {name}")
        if not passed:
            all_passed = False

    print("\n" + ("ALL TESTS PASSED!" if all_passed else "SOME TESTS FAILED"))
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
