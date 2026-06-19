# Plan — Milestone 1: Thin Vertical Slice onto a LlamaIndex ReAct Agent

## Context

`twitter_bot_venice` today is a linear pipeline: poll mentions → `analyse()` → `craft_tweet()` → reply, with deterministic safety checks baked into `venice_api.py`. We want to evolve it into an **autonomous agent** that *decides* which capability to use per tweet (internal knowledge base, live web search, note-taking), using a **LlamaIndex ReAct agent** with **Kimi K2.5** via Venice.

This plan delivers **Milestone 1 only**: a *thin vertical slice* — one end-to-end path through every layer (spam/security pre-filter → ReAct agent → tools → RAG → safety post-filter → output), runnable from a **CLI harness on a single tweet/query**, **not** wired into the live `bot.py` loop. The goal is to prove the whole loop works and is safe before it ever posts unattended.

**Decisions locked with the user:**
- **Upstream-bound** → everything is *additive* (new `agent/` package), *flag-gated* (`USE_AGENT`, default off), reuses existing tested modules verbatim, and ships with offline tests. The proven pipeline stays as the fallback.
- **Safety = mandatory deterministic guardrail** wrapping the agent (the agent can never post around it), reusing `safety.py` exactly.
- **Stateful spam/security pre-filter** (the user's design) as PRE-layer 0: persistent per-user block with a 24h TTL, auto-expiry to catch false positives, escalating re-blocks.
- **First trip** → warn once, then block 24h; re-offense → silent re-block. **Triggers** → security trips (injection/scam URL) **and** spam-rate abuse (flooding). **Storage** → extend `state.json` now (Supabase later).

**Out of scope (later milestones):** wiring the agent into `bot.py`'s live loop behind the flag; multi-model fallback inside the ReAct loop; PandasQueryEngine analytics/ROI; PDF ingestion; Supabase migration.

## Branch

`feat/agent-vertical-slice` off `upstream/main` (new direction; clean base). The earlier audit-fix branches/PRs are unrelated and stay as-is.

## New dependencies (add to `requirements.txt`, keep minimal)
- `llama-index-core`
- `llama-index-llms-openai-like` — Venice via OpenAI-compatible endpoint
- `llama-index-embeddings-openai-like` — Venice embeddings (production)
- `llama-index-embeddings-huggingface` — **dev-only** local embedding fallback (the Venice account currently returns **HTTP 402**, so live embeddings fail). Pulls `sentence-transformers`/torch — heavy; keep it dev-only and document it. Production uses Venice embeddings.

## Key technical findings (verified via current LlamaIndex docs)
- The `ReActAgent.from_tools(...)` is **deprecated**. Use `from llama_index.core.agent.workflow import ReActAgent`; construct with `name/description/system_prompt/tools/llm`; run with `await agent.run(user_msg=...)`, read `str(response)`.
- Venice models advertise **no function-calling** → set `is_function_calling_model=False` → LlamaIndex uses the **text-based ReAct loop** (correct for us).
- Venice's web search is the non-standard `venice_parameters` body field. **Decision: web search is a dedicated tool**, not an LLM kwarg — the tool reuses the proven `venice_api._call_venice(..., force_search=True)` raw path (robust). The reasoning LLM runs with web search **off** (cheap, deterministic reasoning turns).

## Files

### New — `agent/` package (additive)
| File | Responsibility |
|---|---|
| `agent/__init__.py` | package marker |
| `agent/llm.py` | `reasoning_llm()` → `OpenAILike(api_base="https://api.venice.ai/api/v1", is_function_calling_model=False, context_window=…)` for ReAct reasoning |
| `agent/embeddings.py` | `get_embed_model()` → Venice `OpenAILikeEmbedding` if `Config.EMBED_BACKEND=="venice"` else local `HuggingFaceEmbedding` (402 fallback) |
| `agent/knowledge_index.py` | `get_index()` builds a `VectorStoreIndex` from `venice_faqs.json`, persists to `./storage`, loads if present; `knowledge_query_engine_tool()` → `QueryEngineTool` named `Venice_Knowledge_Base` |
| `agent/tools.py` | `venice_search_tool()` (FunctionTool → `_call_venice(force_search=True)`), `note_saver_tool()` (appends to `notes.txt`) |
| `agent/core.py` | `build_agent()` (ReAct + system prompt + tools), `run_agent(query, context, urls, …)` async entry that assembles the user message (mirroring `venice_api.analyse`) + injects `build_url_safety_context` |
| `agent/guardrails.py` | `agent_reply(query, *, context, urls, author_id=None, state=None)` — the **mandatory PRE/POST safety + spam wrapper**; returns `AgentResult(text, trip)` where `trip ∈ {"injection","scam","spam",None}` so the caller records offenses |
| `main_agent.py` (repo root) | CLI harness: tweet URL/ID *or* `--query "…"`; reuses `reply_to_tweet.py`'s context fetch; routes through `agent_reply` when `Config.USE_AGENT` else legacy `analyse`/`craft_tweet`; prints (optional y/n post). Not in `bot.py`. |

### Modified (additive only)
- `config.py` — new fields: `USE_AGENT` (env, default False), `AGENT_MODEL=MODEL_PRIMARY`, `AGENT_CONTEXT_WINDOW=256_000`, `EMBED_BACKEND` (env, default `"local"`), `EMBED_MODEL_VENICE="text-embedding-bge-m3"`, `EMBED_MODEL_LOCAL="BAAI/bge-small-en-v1.5"`, `KNOWLEDGE_STORAGE_DIR="storage"`, `NOTES_FILE="notes.txt"`, `SPAM_BLOCK_HOURS=24`, `SPAM_FLOOD_FACTOR=2` (flood = > factor × per-user hourly cap), `AGENT_SYSTEM_PROMPT = ANALYST_PROMPT + <ReAct tool-usage + char-limit/no-greeting/no-emoji addendum>`.
- `state.py` — extend `State` with the spam guard (see below).
- `.gitignore` — add `storage/` and `notes.txt`.
- `requirements.txt` — new deps above.

## Spam / security pre-filter (extends `State`)

Add to `State` (persisted in `state.json`, bounded + TTL-pruned like `processed`):
- `blocked_until: dict[user_id → epoch_seconds]`, `offense_count: dict[user_id → int]`.
- `is_blocked(user_id, now) -> bool` — true if `now < blocked_until[user_id]`; prunes expired entries (the "clean up after 24h → start listening again" behavior).
- `record_offense(user_id, now) -> None` — increments `offense_count`, sets `blocked_until = now + SPAM_BLOCK_HOURS*3600`, marks dirty.
- `times_offended(user_id) -> int` — to drive "warn once on first offense, silent after."

Tests inject `now` (no wall-clock dependency).

## Guardrail flow (the safety boundary — `agent/guardrails.py`)

```
agent_reply(query, context, urls, author_id, state):
  # PRE-0 spam/security block (caller also pre-checks state.is_blocked to skip entirely)
  if state and author_id and state.is_blocked(author_id, now):
      return AgentResult(text=None, trip="blocked")          # do not engage

  # PRE-1 injection screen (NO agent call on failure)
  is_safe, reason, signals = screen_input_for_injection(f"{query} {context or ''}")
  if not is_safe:
      return AgentResult(get_injection_warning_reply(signals), trip="injection")

  # PRE-2 URL screen (blocked → scam warning, agent never sees it)
  safe, suspicious, blocked = screen_urls(urls)
  if blocked:
      return AgentResult(get_scam_warning_reply(suspicious, blocked), trip="scam")

  # AGENT (only if PRE passes); url-safety context injected inside run_agent
  reply = asyncio.run(run_agent(query, context, urls, safe, suspicious, blocked))
  if not reply: return AgentResult(Config.ERROR_MESSAGE, None)

  # POST-1 censorship → never post a refusal
  if is_censored(reply): return AgentResult(Config.ERROR_MESSAGE, None)

  # POST-2 output scan → never post unsafe text
  ok, why = scan_output(reply, urls)
  if not ok:
      warn = get_injection_warning_reply() if any(k in why.lower() for k in ("token","fee","wallet","ticker")) else get_scam_warning_reply()
      return AgentResult(warn, trip="injection" if "token" in why.lower() else "scam")

  return AgentResult(reply, None)
```

**Caller (CLI now; bot.py later)** owns offense recording + the "warn once then block" policy:
```
if state.is_blocked(author_id, now): skip            # PRE-0, cheap, no agent
result = agent_reply(query, context, urls, author_id, state)
if result.trip in ("injection","scam","spam"):
    first = state.times_offended(author_id) == 0
    state.record_offense(author_id, now)             # blocks 24h
    if first: post(result.text)                      # warn once
    else:     pass                                    # silent re-block
elif result.text: post(result.text)
```
Spam-rate abuse: the caller counts mentions/user/window; if a user exceeds `SPAM_FLOOD_FACTOR × MAX_REPLIES_PER_USER_PER_HOUR`, call `record_offense(...)` (trip `"spam"`). For the CLI slice this path is stubbed/loggable; full enforcement lands when wired into `bot.py`'s loop (Milestone 2).

## Reuse (do not rewrite)
- `safety.py`: `screen_input_for_injection`, `screen_urls`, `scan_output`, `is_censored`, `build_url_safety_context`, `get_scam_warning_reply`, `get_injection_warning_reply`.
- `venice_api.py`: `_call_venice(model, system, user_content, force_search=…)` for the web-search tool.
- `venice_knowledge.py`: `venice_faqs.json` shape for index documents (`_load_faqs` logic).
- `reply_to_tweet.py`: `extract_tweet_id`, context-fetch shape for the harness.
- `config.py`: `ANALYST_PROMPT`/`CRAFTER_PROMPT` constraints, `char_limit()`.

## Verification

**Offline pytest** (default `pytest -m "not live"`; import LlamaIndex lazily / `importorskip` so the suite runs even if deps aren't installed):
- `tests/test_agent_guardrails.py` — with a **stub agent** (`async run` returning canned text, call-counter): injection input → warning + agent never awaited; blocked URL → scam warning, agent not called; benign → passthrough; censored output → fallback; scam/token output → blocked. Assert the right `trip` value each time.
- `tests/test_spam_guard.py` — `record_offense` blocks for 24h (inject `now`); `is_blocked` true within window, false after expiry (auto-cleanup); offense count escalates; round-trips through `save`/`load`.
- `tests/test_agent_knowledge_index.py` — build/persist/load with a **stub embedder** (fixed-dim vectors, offline); second `get_index()` loads without rebuild; tool name/description correct.
- `tests/test_agent_tools.py` — `note_saver` appends to a tmp `NOTES_FILE`; `venice_search_tool` with `_call_venice` monkeypatched returns text; tool metadata names correct.
- Existing suite stays green (slice is additive).

**Manual CLI:**
- `USE_AGENT=false python main_agent.py --query "What is DIEM?"` → legacy path regression sanity.
- `USE_AGENT=true EMBED_BACKEND=local python main_agent.py --query "What is DIEM?"` → builds local index, runs the ReAct loop (verbose shows Thought/Action/Observation). **The end-to-end demo.**
- `USE_AGENT=true python main_agent.py <tweet_url>` → real context fetch + agent reply, print-only.

**Live (blocked today):** `tests/test_live_agent.py` marked `@pytest.mark.live`, skipped without `VENICE_API_KEY`. **Known blocker: the Venice account returns HTTP 402 (no credits)** — both reasoning LLM and Venice embeddings fail live until funded. Dev runs use `EMBED_BACKEND=local`; live reasoning is deferred until credits exist.

## Risks / gotchas
- **ReAct reliability with a text-only model** — Kimi must emit well-formed Thought/Action/Answer. Mitigate with a small tool set (3), explicit system-prompt tool guidance, a `max_iterations`/timeout cap, and the POST guardrail + `ERROR_MESSAGE` fallback so a derailed loop still degrades safely. Legacy path stays default.
- **Latency/cost** — ReAct = N reasoning turns + tool calls (and the web-search tool is itself a full Venice call). Expect ~3–6× the current single pass. Acceptable for a flag-gated harness; **measure before any `bot.py` rollout.**
- **402 credits** — blocks all live model/embedding calls now; local embeddings + offline tests keep dev unblocked. Note: `storage/` is embedding-model-specific — switching `EMBED_BACKEND` requires rebuilding it.
- **Heavy local embed dep** — `sentence-transformers`/torch is large; keep dev-only, document, and don't make it a hard prod dependency.
- **Upstream reviewability** — additive package, flag default off, safety enforced *outside* the agent's control, offline tests included. The reviewer's key check — "can the LLM talk its way past safety?" — answers *no* by construction.
