# Venice X Bot — Code Audit

_Audit date: 2026-06-05 · Repo: `twitter_bot_venice` (@venice_mind)_

> This is the baseline audit that motivates the plans in [`../plans/`](../plans/).
> It is a point-in-time snapshot; do not edit it to reflect later fixes — link a
> plan instead.

---

## Executive Summary

**What it is:** An automated Twitter/X bot that replies to people who mention it,
using Venice AI to generate witty, uncensored answers. It can read images, follow
conversation threads, answer questions about Venice's products, and block crypto
scams and manipulation attempts.

**Overall verdict:** The bot is well-built and genuinely thoughtful, especially
around safety — a large share of the code defends against scams and people trying
to trick it into posting harmful things. It works. But it has a few aging parts
that will quietly cause problems over time, and some easy efficiency wins are
being left on the table.

### The three initial concerns

| Concern | Verdict |
|---|---|
| "It's outdated" | **Partly right.** The AI models it uses are hardcoded by hand. If Venice renames or retires one, the bot breaks silently — it just stops answering, with no alert explaining why. |
| "Maybe it's RAG" | **It's not.** It uses crude keyword-matching to pull Venice facts, not modern "smart search" (RAG). It mostly works, but it's the weakest link in answer quality. |
| "Bad memory system" | **Confirmed.** What it calls memory is just a running list of tweets already answered — and that list grows forever and is rewritten every few minutes. It also keeps no memory of past conversations, so it re-does expensive work every time. |

### Issues that matter most

1. **Silent failure risk (highest priority).** If Venice changes a model name,
   the bot stops working with no warning. A small fix turns this into a clear
   alert.
2. **It slowly bloats itself.** The "memory" file grows without limit and is
   constantly rewritten, degrading performance over months.
3. **It's paying double.** It calls the AI twice for most replies when once would
   do — roughly doubling cost and response time. Every reply also re-fetches
   thread context from the API from scratch.
4. **It can miss messages during busy periods.** It only checks 5 mentions at a
   time, so a spike of activity means some people get ignored.

---

## Findings confirmed against the code

| # | Finding | Evidence | Severity |
|---|---|---|---|
| A | Hardcoded model IDs; no alert when a model 404s | `config.py` `MODEL_PRIMARY`/`MODEL_UNCENSORED`/… ; `venice_api._call_venice` swallows errors → `None` | High |
| B | `state.json` processed-ID set grows unbounded; `state.save()` every loop iteration | `state.py`; `bot.py run()` calls `self.state.save()` each pass | Medium |
| C | Two AI calls per reply (`analyse` + `craft_tweet`) | `bot.py:_process_tweet`; `venice_api.py` | Medium (cost/latency) |
| D | Thread context re-fetched from API every reply, no caching | `bot.py:_extract_context` | Medium |
| E | Only 5 mentions per check; bursts overflow one page | `config.MAX_MENTIONS_PER_CHECK = 5` | Medium |
| F | Keyword FAQ matching, not embeddings/RAG | `venice_knowledge.relevant_faqs` | Low (quality) |

### Additional findings (beyond the original audit)

| # | Finding | Evidence | Severity |
|---|---|---|---|
| G | `state.json` is committed to git despite being in `.gitignore` (tracked before the ignore was added). Every run dirties the working tree. | `git ls-files` lists `state.json`; `.gitignore` also lists it | Medium (hygiene) |
| H | Strips a non-existent handle `@venice_bot`; only `@venice_mind` is live | `bot.py:283` | Low |
| I | README quick-start uses Windows `venv\Scripts\activate` on a Linux-targeted project | `README.md` | Low (docs) |
| J | No test framework / CI; "tests" are manual scripts | `test_local.py`, `mock_test.py` | Low (process) |

---

## Priority order for remediation

1. **A — Silent model failure** (highest priority; safety/availability)
2. **G — Untrack `state.json`** (cheap hygiene win, unblocks clean diffs)
3. **B — Bounded, less-frequent state persistence**
4. **C / D — Collapse the double AI call & cache thread context**
5. **E — Mention pagination for bursts**
6. **F — Better FAQ retrieval** (quality; larger effort)

Each gets its own plan in [`../plans/`](../plans/) as it's picked up.
