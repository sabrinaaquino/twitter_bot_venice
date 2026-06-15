"""
Venice AI API integration — single-pass analysis + tweet crafting.
Kimi K2.5 primary (text+vision), GLM Heretic uncensored fallback.
Includes anti-scam URL screening, output scanning, and censorship detection.
"""
import base64
import re
import logging
import requests
from typing import Optional, List
from config import Config
from safety import (
    screen_urls,
    build_url_safety_context,
    scan_output,
    get_scam_warning_reply,
    get_injection_warning_reply,
    screen_input_for_injection,
    is_censored,
)
from venice_knowledge import relevant_faqs, get_models, summarize_models

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────
_HEADERS = {
    "Authorization": f"Bearer {Config.VENICE_API_KEY}",
    "Content-Type": "application/json",
}
_REF_RE = re.compile(r"\[REF\].*?\[/REF\]", re.DOTALL)
_FINAL_RE = re.compile(r"\[FINAL_REPLY\](.*?)\[/FINAL_REPLY\]", re.DOTALL | re.IGNORECASE)
_NOTES_RE = re.compile(r"\[NOTES\](.*?)\[/NOTES\]", re.DOTALL | re.IGNORECASE)

_BANNED = ("Hey there!", "Hi!", "Hello!", "Stay safe", "Be careful", "Be mindful")

# Keywords that indicate the query needs fresh web data
_FRESH_DATA_KEYWORDS = (
    "price", "cost", "worth", "value", "market", "tvl", "apr", "apy",
    "latest", "current", "now", "today", "recent", "new", "update",
    "news", "announce", "launch", "release", "just", "breaking",
    "vvv", "diem", "staking", "stake", "token", "crypto", "bitcoin", "btc", "eth",
    "model", "models", "venice", "feature", "api",
    "who won", "who is winning", "score", "result", "election",
    "weather", "stock", "stocks",
)


def _http_error_hint(status_code: int) -> Optional[str]:
    """Human-readable hint for a Venice HTTP error status, or None if unknown.

    Turns a bare status code into an actionable cause so logs distinguish a
    billing/auth/renamed-model problem from a transient outage.
    """
    return {
        401: "authentication failed — check VENICE_API_KEY",
        402: "payment required — the Venice account has no credits / a billing issue",
        404: "model not found — it may have been renamed or retired; check config.py",
        429: "rate limited by Venice — backing off",
    }.get(status_code)


def _strip_refs(text: str) -> str:
    return _REF_RE.sub("", text).strip()


def _needs_fresh_data(query: str) -> bool:
    """Check if the query likely needs live web data."""
    q_lower = query.lower()
    return any(kw in q_lower for kw in _FRESH_DATA_KEYWORDS)


_VENICE_TOPIC_KEYWORDS = (
    "venice", "vvv", "svvv", "diem", "stake", "staking", "tokenomics",
    "token", "mint", "inference", "pro plan", "subscription", "api credit",
)
_MODEL_KEYWORDS = (
    "model", "models", "context window", "context length", "vision",
    "reasoning", "cheapest", "capabilit", "which model", "kimi", "glm",
    "qwen", "uncensored", "multimodal",
)


def _is_venice_topic(text: str) -> bool:
    t = text.lower()
    return any(k in t for k in _VENICE_TOPIC_KEYWORDS)


def _is_model_question(text: str) -> bool:
    t = text.lower()
    return any(k in t for k in _MODEL_KEYWORDS)


def _venice_params(urls: Optional[List[str]] = None, force_search: bool = False) -> dict:
    """
    Standard Venice parameters with web search + scraping.
    
    force_search=True will always enable web search (for time-sensitive queries).
    Otherwise uses 'auto' to let Venice decide.
    
    Note: Venice API expects string values 'on'/'off'/'auto' for enable_web_search.
    """
    params = {
        "enable_web_search": "on" if force_search else "auto",
        "enable_web_scraping": True,
        "enable_web_citations": False,
        "include_venice_system_prompt": False,
    }
    if urls:
        params["web_search_urls"] = urls
    return params


def _call_venice(
    model: str,
    system: str,
    user_content,
    urls: Optional[List[str]] = None,
    temperature: float = 0.7,
    force_search: bool = False,
) -> Optional[str]:
    """Fire a single chat completion request. Returns stripped text or None."""
    payload = {
        "model": model,
        "temperature": temperature,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_content},
        ],
        "venice_parameters": _venice_params(urls, force_search=force_search),
    }
    try:
        r = requests.post(
            Config.VENICE_URL, json=payload, headers=_HEADERS,
            timeout=Config.VENICE_REQUEST_TIMEOUT_SECONDS,
        )
        r.raise_for_status()
        text = r.json()["choices"][0]["message"]["content"].strip()
        return _strip_refs(text)
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else None
        hint = _http_error_hint(status) if status else None
        if hint:
            # Auth/billing/renamed-model errors are config problems, not transient —
            # log them loudly so they don't hide behind the fallback cascade.
            logger.error(f"Venice API error ({model}): HTTP {status} — {hint}")
        else:
            logger.error(f"Venice API error ({model}): {e}")
        return None
    except Exception as e:
        logger.error(f"Venice API error ({model}): {e}")
        return None


# ── Public API ───────────────────────────────────────────────────

def analyse(
    query: str,
    *,
    context: Optional[str] = None,
    image_bytes: Optional[bytes] = None,
    image_url: Optional[str] = None,
    urls: Optional[List[str]] = None,
) -> str:
    """
    Step 1: Analyse the user's query with full context.
    Kimi K2.5 handles both text AND vision (it's natively multimodal).

    Model cascade:
      1. Kimi K2.5 (primary, text+vision)
      2. If censored → GLM Heretic (uncensored, text-only)
      3. If vision and Kimi fails → Qwen3-VL (vision fallback)
      4. Last resort → Venice Uncensored

    SAFETY:
    - INPUT PRE-SCREENING: Token creation injection attempts are blocked immediately
    - URLs are pre-screened. Suspicious/blocked URLs are NOT scraped —
      instead the AI is told they're unverified/scam so it can warn the user.
    """
    char_limit = Config.char_limit()
    has_image = bool(image_bytes or image_url)

    # ── TOKEN CREATION INJECTION SCREENING ──
    # Check BOTH query and context for injection attempts
    full_text = f"{query} {context or ''}"
    is_safe, reason, signals = screen_input_for_injection(full_text)
    if not is_safe:
        logger.warning(f"🚫 Input blocked (injection): {reason}")
        return get_injection_warning_reply(signals)

    # ── URL SAFETY SCREENING ──
    raw_urls = urls or []
    safe_urls, suspicious_urls, blocked_urls = screen_urls(raw_urls)

    if blocked_urls:
        logger.warning(f"🚫 Blocked scam URL(s) — returning scam warning: {blocked_urls}")
        return get_scam_warning_reply(suspicious_urls, blocked_urls)

    # ── Build user message ──
    if context:
        if context.startswith("[CONTINUING]"):
            clean = context.replace("[CONTINUING] ", "").replace("[CONTINUING]", "")
            msg = f'CONTINUING CONVERSATION — Previous: "{clean}"\nUser now says: "{query}"'
        else:
            msg = f'CONTEXT (original tweet): "{context}"\nUser asks: "{query}"'
    else:
        msg = query

    url_context = build_url_safety_context(safe_urls, suspicious_urls, blocked_urls)
    if url_context:
        msg += f"\n\n{url_context}"

    # ── Authoritative Venice knowledge injection ──
    full_topic_text = f"{query} {context or ''}"
    knowledge_parts = []
    if _is_venice_topic(full_topic_text):
        faqs = relevant_faqs(query, context)
        if faqs:
            knowledge_parts.append("FAQ:\n" + "\n\n".join(faqs))
    if _is_model_question(full_topic_text):
        models = get_models()
        if models:
            knowledge_parts.append("CURRENT VENICE MODELS:\n" + summarize_models(models))
    if knowledge_parts:
        msg += (
            "\n\nAUTHORITATIVE VENICE FACTS (from venice.ai/faqs and the Venice "
            "models API — trust these over your own knowledge):\n"
            + "\n\n".join(knowledge_parts)
        )

    safe_limit = max(1, char_limit - 15)
    msg += (
        f"\n\nOUTPUT (strict):\n"
        f"[FINAL_REPLY]\n"
        f"<your tweet-ready reply, plain text, no greetings/hashtags/markdown>\n"
        f"[/FINAL_REPLY]\n\n"
        f"[NOTES]\n(optional) key facts/sources used\n[/NOTES]\n\n"
        f"HARD LENGTH LIMIT: the text inside [FINAL_REPLY] MUST be {char_limit} characters "
        f"or fewer. Count the characters before finishing. Aim for {safe_limit} or fewer for "
        f"a safety margin. If your draft runs long, tighten and cut words until it fits — "
        f"never exceed {char_limit}. Going over forces a wasteful rewrite, so fit it the first time."
    )

    # ── Build multimodal content if image present ──
    if has_image:
        if image_url:
            img_part = {"type": "image_url", "image_url": {"url": image_url}}
        else:
            b64 = base64.b64encode(image_bytes).decode()
            img_part = {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{b64}"}}
        user_content_vision = [{"type": "text", "text": msg}, img_part]
    else:
        user_content_vision = None

    # Text-only version (for non-vision models like GLM Heretic)
    user_content_text = msg

    # ── Determine if we should force web search ──
    # Queries about prices, current events, Venice updates, etc. need fresh data
    full_query = f"{query} {context or ''}"
    force_search = _needs_fresh_data(full_query)
    if force_search:
        logger.info("🔍 Query needs fresh data — forcing web search")

    # ── MODEL CASCADE ──
    # 1. Kimi K2.5 — primary for everything (text + vision)
    content = user_content_vision if has_image else user_content_text
    result = _call_venice(
        Config.MODEL_PRIMARY, Config.ANALYST_PROMPT, content,
        urls=safe_urls or None, force_search=force_search
    )

    # 2. Censorship check → retry with GLM Heretic (uncensored, text-only)
    if is_censored(result):
        logger.info("🔓 Primary model censored — retrying with GLM Heretic (uncensored)")
        uncensored = _call_venice(
            Config.MODEL_UNCENSORED, Config.ANALYST_PROMPT, user_content_text,
            urls=safe_urls or None, force_search=force_search,
        )
        if uncensored and not is_censored(uncensored):
            result = uncensored
        else:
            logger.warning("🔓 GLM Heretic also censored or failed — trying last resort")
            last = _call_venice(
                Config.MODEL_LAST_RESORT, Config.ANALYST_PROMPT, user_content_text,
                urls=safe_urls or None, force_search=force_search,
            )
            if last and not is_censored(last):
                result = last
            elif uncensored:
                # All models censored — use GLM Heretic's output anyway (least censored)
                logger.warning("🔓 All models censored — using GLM Heretic response as-is")
                result = uncensored

    # 3. If primary failed entirely (not censored, just errored) — try vision fallback or text fallback
    if not result:
        if has_image:
            logger.warning("Primary failed on vision — trying Qwen3-VL")
            result = _call_venice(
                Config.MODEL_VISION_FALLBACK, Config.ANALYST_PROMPT,
                user_content_vision, urls=safe_urls or None, force_search=force_search,
            )
        if not result:
            logger.warning("Trying GLM Heretic as general fallback")
            result = _call_venice(
                Config.MODEL_UNCENSORED, Config.ANALYST_PROMPT,
                user_content_text, urls=safe_urls or None, force_search=force_search,
            )
        if not result:
            result = _call_venice(
                Config.MODEL_LAST_RESORT, Config.ANALYST_PROMPT,
                user_content_text, urls=safe_urls or None, force_search=force_search,
            )

    return result or Config.ERROR_MESSAGE


def craft_tweet(
    analysis: str,
    *,
    use_vision: bool = False,  # kept for API compat; not used in model selection
    context_urls: Optional[List[str]] = None,
) -> str:
    """
    Step 2: Shape the analysis into a final tweet.
    If the analysis already contains a valid [FINAL_REPLY], use it directly.
    Otherwise, ask the crafter model to rewrite.

    SAFETY: Final output is scanned for scam endorsement AND censorship.
    """
    char_limit = Config.char_limit()

    # Try to extract a ready-made reply
    m = _FINAL_RE.search(analysis)
    if m:
        candidate = _strip_refs(m.group(1).strip())
        if len(candidate) <= char_limit and not any(b in candidate for b in _BANNED):
            if not is_censored(candidate):
                is_safe, reason = scan_output(candidate, context_urls)
                if not is_safe:
                    logger.warning(f"🚨 Candidate reply blocked: {reason}")
                    return get_scam_warning_reply()
                return candidate
            # Candidate was censored — fall through to uncensored rewrite
            logger.info("🔓 FINAL_REPLY was censored — rewriting with uncensored model")

    # Notes for context
    notes_m = _NOTES_RE.search(analysis)
    notes = notes_m.group(1).strip() if notes_m else ""

    source_text = m.group(1).strip() if m else analysis
    prompt = (
        f"Rewrite into a tweet (≤{char_limit} chars). "
        f"Keep all facts. Plain text only.\n\n"
        f"SOURCE:\n{source_text}\n\n"
        f"NOTES:\n{notes}" if notes else
        f"Rewrite into a tweet (≤{char_limit} chars). "
        f"Keep all facts. Plain text only.\n\n"
        f"SOURCE:\n{source_text}"
    )

    # Try primary first, then uncensored if it self-censors
    result = _call_venice(Config.MODEL_PRIMARY, Config.CRAFTER_PROMPT, prompt, temperature=0.6)

    if is_censored(result):
        logger.info("🔓 Crafter censored — retrying with GLM Heretic")
        result = _call_venice(Config.MODEL_UNCENSORED, Config.CRAFTER_PROMPT, prompt, temperature=0.6)

    if not result or len(result) > char_limit or any(b in result for b in _BANNED):
        strict = (
            f"CRITICAL: must be ≤{char_limit} chars. No greetings, no hashtags. "
            f"Rewrite this:\n{source_text}"
        )
        # Use uncensored model for strict rewrite — it won't refuse
        result = _call_venice(Config.MODEL_UNCENSORED, Config.CRAFTER_PROMPT, strict, temperature=0.5)

    if not result:
        result = _call_venice(Config.MODEL_LAST_RESORT, Config.CRAFTER_PROMPT, prompt, temperature=0.5)

    if not result:
        return Config.ERROR_MESSAGE

    # ── OUTPUT SAFETY SCAN ──
    is_safe, reason = scan_output(result, context_urls)
    if not is_safe:
        logger.warning(f"🚨 Final reply blocked: {reason}")
        # Use appropriate warning based on what was detected
        if any(kw in reason.lower() for kw in ("token", "fee", "wallet", "ticker")):
            return get_injection_warning_reply()
        return get_scam_warning_reply()

    return result
