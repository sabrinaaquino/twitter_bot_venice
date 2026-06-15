# docs/

Plans, audits, and the **why** behind larger changes to `twitter_bot_venice`.

Write the reasoning down *before* the big change, so reviewers (and future
agents) can see the intent, not just the diff.

## Contents

- [`audits/2026-06-05-code-audit.md`](audits/2026-06-05-code-audit.md) — initial
  codebase audit (the baseline that motivates the current plans).
- [`plans/`](plans/) — proposed and in-progress changes, each with rationale,
  scope, and a verification step.

## How to use this folder

- One file per plan or audit. Prefix with a date (`YYYY-MM-DD-`) when it's a
  point-in-time snapshot.
- A plan states: **the problem**, **why it matters**, **the proposed fix**, and
  **how we'll verify it**. Link back to the audit finding it addresses.
- Update the plan's status as work lands (`Proposed` → `In progress` → `Done`).
