# Plan 0001 — Detect & alert on unavailable Venice models

- **Status:** Proposed
- **Addresses:** Audit finding **A** (silent model failure — highest priority)
- **Date:** 2026-06-08

## The problem

Model IDs are hardcoded in `config.py`:

```python
MODEL_PRIMARY        = "kimi-k2-5"
MODEL_UNCENSORED     = "olafangensan-glm-4.7-flash-heretic"
MODEL_VISION_FALLBACK = "qwen3-vl-235b-a22b"
MODEL_LAST_RESORT    = "venice-uncensored"
```

When Venice renames or retires a model, `_call_venice()` gets a 4xx, logs a
generic `Venice API error`, and returns `None`. The cascade then walks down to
the next model. If the *primary* is the one that's gone, every reply silently
degrades to a weaker/uncensored fallback — or, if several are gone, the bot just
stops replying. **There is no signal that the cause is a bad model ID.** An
operator sees "bot is quiet" with no actionable error.

## Why it matters

- Highest-priority finding: it's a silent availability/quality failure.
- Venice ships and renames models frequently (the snapshot is refreshed on a
  cron for exactly this reason) — so this *will* happen.
- The fix is small and the payoff is a clear, early, actionable alert.

## Proposed fix

Two complementary, low-risk changes:

### 1. Validate configured model IDs at startup
The live models list is already available via
`venice_knowledge.get_models()` (6h TTL, snapshot fallback). On boot, compare the
four configured `MODEL_*` IDs against the set of live model IDs:

- Any configured ID **not** present → log at `CRITICAL` with the exact missing
  ID and the closest available names, so the operator knows what to update.
- If the primary is missing, make it loud (this is the degradation case).
- Non-fatal by default (the bot can still limp on fallbacks), but the alert is
  unmissable. A `STRICT_MODEL_VALIDATION` flag could make it fatal later.

This runs once in `VeniceBot.__init__` (or `main`), not per-request — no added
latency on the hot path.

### 2. Distinguish "model not found" from generic errors in `_call_venice`
Inspect the HTTP status / error body. On a 404 / "model not found", log at
`ERROR`/`CRITICAL` naming the offending model ID explicitly, rather than the
current generic `Venice API error (<model>): <e>`. This makes the cascade's
fallbacks attributable in the logs.

## Out of scope (future plans)

- Auto-selecting models dynamically from the live list (larger behavioural
  change — separate plan).
- Pushing alerts to an external channel (Slack/email/PagerDuty). Start with loud
  logs; wire external alerting later if needed.

## How we'll verify

- `python test_local.py --offline-only` still passes (no regressions in the
  offline-safe paths).
- Add/extend an offline test that feeds a fake models list missing the primary
  ID and asserts the validation reports it.
- Manual: temporarily set `MODEL_PRIMARY` to a bogus ID and confirm a single
  clear `CRITICAL` log line on startup naming it.

## Rollout

- Branch: `fix/model-availability-alerting`
- One commit for the validation + logging change; plan doc committed alongside or
  just before.
