# Venice X Bot (@venice_mind)

A Twitter bot powered by Venice AI with a Grok-style personality — witty, direct, uncensored.

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
