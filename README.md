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
cd twitter_bot_venice
python -m venv venv

# Activate the virtualenv:
source venv/bin/activate        # Linux / macOS
# venv\Scripts\activate         # Windows (PowerShell/cmd)

pip install -r requirements.txt
cp env_example.txt .env   # then edit .env and fill in your keys
python main.py
```

> Requires Python 3.10+. Without valid keys in `.env`, `python main.py` exits
> immediately with a clear `CRITICAL | Fatal: 401 Unauthorized` — that's
> expected. To check the install without keys, run the offline tests below.

## Testing

Automated tests use **pytest** (a dev dependency):

```bash
pip install pytest

pytest               # offline suite — no API keys needed (the default)
pytest -m live       # live Venice API tests (require VENICE_API_KEY)
```

The offline suite covers the safety layer, knowledge retrieval, the agent
guardrail, the spam guard, and the bot loop. The loop tests drive `bot.py` with
a fake Twitter client (`tests/test_bot_loop.py`), so no real credentials are
needed.

### Trying the agent by hand

```bash
# One query through the ReAct agent, with the reasoning trace
USE_AGENT=true python main_agent.py --query "what is DIEM?" --verbose

# The legacy pipeline, for comparison
python main_agent.py --query "what is DIEM?"
```

**FAQ retrieval backend** (`KNOWLEDGE_BACKEND`, default `keyword`): the agent looks
up Venice facts from the committed FAQ. `keyword` (default) uses a dependency-free
keyword scorer — right-sized for the small (~90 Q&A) FAQ and needs no embeddings.
Set `KNOWLEDGE_BACKEND=vector EMBED_BACKEND=venice` to use semantic vector search
instead (installs `llama-index-embeddings-*`; see `requirements.txt`).

### Dry-run against real mentions (no posting)

```bash
DRY_RUN=true USE_AGENT=true EMBED_BACKEND=venice python main.py
```

Polls real mentions and **logs** the would-be reply instead of posting — fully
read-only, so only `TWITTER_BEARER_TOKEN` is required (set `BOT_USERNAME` to the
account whose mentions to watch). See [Configuration](#configuration) for
`USE_AGENT` / `DRY_RUN`.

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
