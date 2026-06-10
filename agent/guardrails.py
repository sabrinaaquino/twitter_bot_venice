"""The mandatory deterministic safety boundary around the agent.

Safety is NOT an agent-callable tool — it's enforced here, outside the agent's
control, so the LLM can never talk its way past it. The agent only runs *between*
the PRE screens and the POST scans; every blocking path returns before/without
posting unsafe text.

Reuses safety.py verbatim (same functions and ordering as venice_api.analyse /
craft_tweet), so the agent path inherits identical guarantees.
"""
import asyncio
import logging
from dataclasses import dataclass
from typing import Optional

from config import Config
from safety import (
    screen_input_for_injection,
    screen_urls,
    scan_output,
    is_censored,
    get_scam_warning_reply,
    get_injection_warning_reply,
)

logger = logging.getLogger(__name__)


def fit_to_limit(text: str, limit: int) -> str:
    """Hard length backstop: guarantee len(text) <= limit, breaking on a sentence
    boundary when one falls in the last ~30% (mirrors twitter_client.reply_to_tweet).

    The agent's prompt already aims for the limit; this only fires on the rare
    overshoot, so the reply on the agent path can never exceed the tweet limit.
    """
    if len(text) <= limit:
        return text
    head = text[: limit - 1]
    for punct in (". ", "! ", "? "):
        idx = head.rfind(punct)
        if idx > limit * 0.7:
            return text[: idx + 1]
    return head.rstrip() + "…"


@dataclass
class AgentResult:
    """Outcome of a guarded agent reply.

    text: the reply to post (or a canned warning), or None if we must not engage.
    trip: which screen tripped — "blocked" | "injection" | "scam" | None.
          The caller uses this to record a spam/security offense.
    """
    text: Optional[str]
    trip: Optional[str] = None


async def agent_reply_async(
    query: str,
    *,
    context: Optional[str] = None,
    urls=None,
    author_id=None,
    state=None,
    now: Optional[float] = None,
    agent=None,
    verbose: bool = False,
) -> AgentResult:
    urls = urls or []

    # ── PRE-0: already-blocked user → do not engage (cheap, no agent) ──
    if state is not None and author_id is not None and now is not None:
        if state.is_blocked(author_id, now):
            logger.info(f"Skipping blocked user {author_id}")
            return AgentResult(text=None, trip="blocked")

    # ── PRE-1: injection screen (agent never runs on failure) ──
    is_safe, reason, signals = screen_input_for_injection(f"{query} {context or ''}")
    if not is_safe:
        logger.warning(f"Input blocked (injection): {reason}")
        return AgentResult(get_injection_warning_reply(signals), trip="injection")

    # ── PRE-2: URL screen (blocked → scam warning; agent never sees it) ──
    safe_urls, suspicious_urls, blocked_urls = screen_urls(urls)
    if blocked_urls:
        logger.warning(f"Blocked scam URL(s): {blocked_urls}")
        return AgentResult(get_scam_warning_reply(suspicious_urls, blocked_urls), trip="scam")

    # ── AGENT (only reached if PRE passed) ──
    from agent.core import run_agent
    reply = await run_agent(
        query,
        context=context,
        safe_urls=safe_urls,
        suspicious_urls=suspicious_urls,
        blocked_urls=blocked_urls,
        agent=agent,
        verbose=verbose,
    )
    if not reply:
        return AgentResult(Config.ERROR_MESSAGE, None)

    # ── POST-1: censorship → never post a refusal ──
    if is_censored(reply):
        logger.warning("Agent output censored — returning safe fallback")
        return AgentResult(Config.ERROR_MESSAGE, None)

    # ── POST-2: output scan → never post unsafe text ──
    out_safe, why = scan_output(reply, urls)
    if not out_safe:
        logger.warning(f"Agent output blocked: {why}")
        if any(k in why.lower() for k in ("token", "fee", "wallet", "ticker")):
            return AgentResult(get_injection_warning_reply(), trip="injection")
        return AgentResult(get_scam_warning_reply(), trip="scam")

    # ── POST-3: hard length backstop (safe to truncate scanned text) ──
    char_limit = Config.char_limit()
    if len(reply) > char_limit:
        logger.info(f"Agent reply over limit ({len(reply)} > {char_limit}) — truncating")
        reply = fit_to_limit(reply, char_limit)

    return AgentResult(reply, None)


def agent_reply(
    query: str,
    *,
    context: Optional[str] = None,
    urls=None,
    author_id=None,
    state=None,
    now: Optional[float] = None,
    agent=None,
    verbose: bool = False,
) -> AgentResult:
    """Synchronous wrapper for the CLI harness."""
    return asyncio.run(agent_reply_async(
        query, context=context, urls=urls,
        author_id=author_id, state=state, now=now, agent=agent, verbose=verbose,
    ))
