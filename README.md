# Venice X Bot (@venice_mind)

A Twitter bot powered by Venice AI — witty, direct, uncensored.

## Features

- **Kimi K2.5** as primary model (256K context, text + vision)
- **GLM Heretic** fallback when primary self-censors
- **Real-time web search** for prices, news, and current events
- **Anti-scam protection** — blocks phishing URLs, warns about lookalikes
- **Thread-aware** — fetches parent tweets and conversation context

## Quick Start

```bash
cd venice-x-bot/twitter_bot_venice
python -m venv venv && venv\Scripts\activate
pip install -r requirements.txt
cp env_example.txt .env   # fill in your keys
python main.py
```

## Testing

```bash
# Run offline tests
python test_local.py --offline-only

# Test a specific tweet
python reply_to_tweet.py https://x.com/user/status/1234567890

# Run mock queries
python mock_test.py
```

## Refreshing Venice knowledge

The bot answers Venice questions from a committed FAQ snapshot and the live
models API. Re-sync the snapshots whenever Venice updates its FAQ or models:

```bash
python scripts/fetch_venice_data.py   # rewrites venice_faqs.json + venice_models.json
```

Run it manually or via cron. Model data is also fetched live at runtime (6h
cache); the snapshot is the offline fallback. Commit the updated JSON files.

## Project Structure

```
twitter_bot_venice/
├── main.py              # Entry point
├── bot.py               # Mention polling + processing
├── config.py            # Models, prompts, settings
├── venice_api.py        # Venice API calls
├── safety.py            # Anti-scam URL screening
├── twitter_client.py    # Twitter API wrappers
├── state.py             # Processed-tweet persistence
└── test_local.py        # Test suite
```

## Models

| Model | Role | Context |
|-------|------|---------|
| Kimi K2.5 | Primary (text + vision) | 256K |
| GLM 4.7 Flash Heretic | Uncensored fallback | 128K |
| Qwen3-VL 235B | Vision backup | 256K |
| Venice Uncensored | Last resort | 32K |

## Configuration

Key settings in `config.py`:

| Setting | Default | Description |
|---------|---------|-------------|
| `MAX_TWEET_AGE_MINUTES` | 60 | Ignore older tweets |
| `MAX_REPLIES_PER_HOUR` | 30 | Rate limit |
| `X_PREMIUM_ENABLED` | false | 25K char limit if true |

## Security

The bot includes multi-layer anti-scam protection:

1. **URL screening** — classifies URLs as trusted/suspicious/blocked
2. **Selective scraping** — only trusted domains are scraped
3. **Prompt hardening** — AI knows only venice.ai is official
4. **Output scanning** — blocks replies that endorse scam URLs

### Trusted Domains

Only these are treated as official Venice:
- `venice.ai` and subdomains
- Official social accounts
- Blockchain explorers (etherscan, basescan, etc.)

### Adding Scam Domains

Edit `safety.py`:
- `BLOCKLISTED_DOMAINS` — known scam domains
- `_SCAM_URL_PATTERNS` — regex patterns (claim, airdrop, etc.)

## Environment Variables

```
TWITTER_BEARER_TOKEN=
TWITTER_API_KEY=
TWITTER_API_SECRET=
TWITTER_ACCESS_TOKEN=
TWITTER_ACCESS_TOKEN_SECRET=
VENICE_API_KEY=
X_PREMIUM_ENABLED=false
```

## Pairing with GetXAPI for Cheaper Read Operations (Optional)

For users who need a cheaper or higher-rate-limit option for read-only Twitter (X) operations such as tweet search, profile lookup, and follower lists, this project can be paired with [GetXAPI](https://getxapi.com), a budget Twitter / X data API priced at $0.05 per 1K tweets versus the official X API basic tier at $200 / month.

Two integration patterns:

1. **Run side-by-side in your AI client.** Keep this project for its primary workflow and add the [official GetXAPI MCP server](https://github.com/getxapi/getxapi-mcp) for read-heavy tasks. Each tool name routes to the backend best suited for that operation.

2. **Add a backend toggle.** For a code-level reference of an optional alternative backend behind a single env variable, see the [PR pattern merged into a sibling project](https://github.com/GenAIwithMS/twitter-mcp/pull/3).

GetXAPI quick start:

- Signup with $0.50 free credit (no card required): https://getxapi.com/signup
- Official GetXAPI MCP server: https://github.com/getxapi/getxapi-mcp
- npm: `@getxapi/mcp`
- Pay-per-call pricing: $0.001 / call, $0.05 / 1K tweets

This pairing is fully optional. No behavior change for existing users.

