#!/usr/bin/env python3
"""Quick mock tweet tests."""
import sys
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from venice_api import analyse, craft_tweet, _needs_fresh_data

def test(name, query, urls=None):
    print("=" * 60)
    print(f"MOCK: {name}")
    print("=" * 60)
    print(f"Query: {query}")
    print(f"Force search: {_needs_fresh_data(query)}")
    if urls:
        print(f"URLs: {urls}")
    
    result = analyse(query, urls=urls)
    final = craft_tweet(result, context_urls=urls)
    
    print(f"\nFINAL TWEET ({len(final)} chars):")
    print("-" * 40)
    print(final)
    print("-" * 40)
    
    # Check for emojis
    import re
    emoji_pattern = re.compile("["
        u"\U0001F600-\U0001F64F"  # emoticons
        u"\U0001F300-\U0001F5FF"  # symbols & pictographs
        u"\U0001F680-\U0001F6FF"  # transport & map symbols
        u"\U0001F1E0-\U0001F1FF"  # flags
        u"\U00002702-\U000027B0"
        u"\U000024C2-\U0001F251"
        u"\U00002600-\U000026FF"  # misc symbols
        u"\U00002700-\U000027BF"  # dingbats
        "]+", flags=re.UNICODE)
    if emoji_pattern.search(final):
        print("WARNING: Response contains emojis!")
    else:
        print("OK: No emojis detected")
    print()
    return final

if __name__ == "__main__":
    # Test 1: Scam URL
    test("Scam URL Detection", 
         "Is this site legit?", 
         urls=["https://vvvevent.com/claim"])
    
    # Test 2: Simple question
    test("Simple Question",
         "What is Venice AI in one sentence?")
