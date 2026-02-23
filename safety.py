"""
Safety layer — domain allowlisting, URL screening, output scanning, anti-injection,
and censorship detection.

Defence layers:
1. URL PRE-SCREENING  — flag/strip unknown domains before the AI sees them
2. PROMPT HARDENING   — system prompt tells AI to distrust non-allowlisted domains
3. OUTPUT SCANNING    — catch replies that endorse/link suspicious URLs before posting
4. SCAM PATTERN DETECTION — heuristic checks for common crypto phishing patterns
5. CENSORSHIP DETECTION — detect when a model self-censors, trigger uncensored fallback
"""
import re
import logging
from urllib.parse import urlparse
from typing import List, Tuple, Optional

logger = logging.getLogger(__name__)

# ── Official Venice domains (ONLY these are trusted) ─────────────
OFFICIAL_DOMAINS = frozenset({
    "venice.ai",
    "www.venice.ai",
    "app.venice.ai",
    "api.venice.ai",
    "docs.venice.ai",
    "blog.venice.ai",
    # Social accounts
    "x.com/venice_ai",
    "twitter.com/venice_ai",
    "x.com/venicemindshare",
    "twitter.com/venicemindshare",
    "x.com/VeniceAiPro",
    "twitter.com/VeniceAiPro",
    "discord.gg/venice",
    "discord.com/invite/venice",
    "github.com/veniceai",
    "t.me/venice_ai",
    # Known safe third-party
    "etherscan.io",
    "basescan.org",
    "dexscreener.com",
    "coingecko.com",
    "coinmarketcap.com",
    "defillama.com",
    "chainpatrol.io",
    "app.chainpatrol.io",
})

# Domains that are NEVER safe (known scam patterns)
BLOCKLISTED_DOMAINS = frozenset({
    "vvvevent.com",
    "venice-ai.com",
    "veniceai.org",
    "venicetoken.com",
    "vvvclaim.com",
    "venice-claim.com",
    "veniceairdrop.com",
})

# ── Scam URL heuristics ──────────────────────────────────────────
# Patterns in URLs/domains that strongly indicate phishing
_SCAM_URL_PATTERNS = [
    r"claim",           # "claim your tokens"
    r"airdrop",         # fake airdrops
    r"connect[-_]?wallet",
    r"mint[-_]?free",
    r"free[-_]?mint",
    r"presale",
    r"whitelist[-_]?spot",
    r"allocation",
    r"seed[-_]?phrase",
    r"recovery[-_]?phrase",
    r"private[-_]?key",
]
_SCAM_URL_RE = re.compile("|".join(_SCAM_URL_PATTERNS), re.IGNORECASE)

# Lookalike detection: domains designed to impersonate Venice
_VENICE_LOOKALIKE_RE = re.compile(
    r"v+e*n+i*c+e|vvv|diem", re.IGNORECASE
)

# ── Output scanning patterns ─────────────────────────────────────
# If the bot's reply contains these + a non-official URL, BLOCK it
_ENDORSEMENT_PATTERNS = [
    r"official",
    r"legitimate",
    r"verified",
    r"authentic",
    r"real deal",
    r"matches the official",
    r"associated with venice",
    r"from venice",
    r"venice ai.*event",
    r"event.*venice ai",
    r"connect your wallet",
    r"enter your.*phrase",
    r"exclusive.*holder",
    r"token.*allocation",
]
_ENDORSEMENT_RE = re.compile("|".join(_ENDORSEMENT_PATTERNS), re.IGNORECASE)


# ═════════════════════════════════════════════════════════════════
# PUBLIC API
# ═════════════════════════════════════════════════════════════════

def is_official_domain(url: str) -> bool:
    """Check if a URL belongs to an official Venice domain."""
    try:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        host = (parsed.hostname or "").lower().lstrip("www.")
        # Exact domain match
        if host in OFFICIAL_DOMAINS or f"www.{host}" in OFFICIAL_DOMAINS:
            return True
        # Path-based matches (for social links like x.com/venice_ai)
        full = f"{host}{parsed.path}".rstrip("/").lower()
        for official in OFFICIAL_DOMAINS:
            if full.startswith(official):
                return True
        return False
    except Exception:
        return False


def is_blocklisted(url: str) -> bool:
    """Check if URL is on the explicit blocklist."""
    try:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        host = (parsed.hostname or "").lower().lstrip("www.")
        return host in BLOCKLISTED_DOMAINS or f"www.{host}" in BLOCKLISTED_DOMAINS
    except Exception:
        return False


def classify_url(url: str) -> str:
    """
    Classify a URL as 'trusted', 'blocked', 'suspicious', or 'unknown'.
    """
    if is_blocklisted(url):
        return "blocked"
    if is_official_domain(url):
        return "trusted"

    try:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        host = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
        full = host + path

        # Venice lookalike domain?
        if _VENICE_LOOKALIKE_RE.search(host):
            logger.warning(f"🚨 Venice lookalike domain detected: {host}")
            return "suspicious"

        # Scam URL patterns in the path or domain?
        if _SCAM_URL_RE.search(full):
            logger.warning(f"🚨 Scam URL pattern detected: {url}")
            return "suspicious"

    except Exception:
        pass

    return "unknown"


def screen_urls(urls: List[str]) -> Tuple[List[str], List[str], List[str]]:
    """
    Screen a list of URLs. Returns (safe_urls, suspicious_urls, blocked_urls).
    Safe URLs are passed to the AI. Suspicious/blocked URLs are flagged in context.
    """
    safe = []
    suspicious = []
    blocked = []

    for url in urls:
        cls = classify_url(url)
        if cls == "trusted":
            safe.append(url)
        elif cls == "blocked":
            blocked.append(url)
            logger.warning(f"🚫 BLOCKED URL: {url}")
        elif cls == "suspicious":
            suspicious.append(url)
            logger.warning(f"⚠️ SUSPICIOUS URL: {url}")
        else:
            # Unknown — don't scrape it, but inform the AI about it
            suspicious.append(url)

    return safe, suspicious, blocked


def build_url_safety_context(
    safe: List[str], suspicious: List[str], blocked: List[str]
) -> str:
    """
    Build a context string that tells the AI about URL classifications.
    This is injected into the user message so the model knows what's safe.
    """
    parts = []

    if safe:
        parts.append("TRUSTED LINKS (official/verified):\n" + "\n".join(safe))

    if suspicious:
        parts.append(
            "[UNVERIFIED/SUSPICIOUS LINKS] (DO NOT endorse these as official, "
            "DO NOT say they are from Venice AI, WARN the user if they look like scams):\n"
            + "\n".join(suspicious)
        )

    if blocked:
        parts.append(
            "🚫 KNOWN SCAM LINKS (these are confirmed phishing — "
            "WARN the user these are dangerous):\n"
            + "\n".join(blocked)
        )

    return "\n\n".join(parts) if parts else ""


def scan_output(reply: str, context_urls: List[str] = None) -> Tuple[bool, str]:
    """
    Scan the bot's generated reply for dangerous endorsements.
    Returns (is_safe, reason).

    BLOCKS the reply if it endorses a non-official URL as legitimate/official.
    """
    context_urls = context_urls or []

    # Collect all URLs in the reply
    reply_urls = re.findall(r"https?://[^\s)\"']+", reply, re.IGNORECASE)
    all_urls = reply_urls + context_urls

    # Check: does the reply endorse something AND contain a non-official URL?
    has_endorsement = bool(_ENDORSEMENT_RE.search(reply))

    non_official_urls = [u for u in all_urls if not is_official_domain(u)]
    has_suspicious_url = any(classify_url(u) in ("suspicious", "blocked") for u in non_official_urls)

    if has_endorsement and has_suspicious_url:
        flagged_urls = [u for u in non_official_urls if classify_url(u) in ("suspicious", "blocked")]
        reason = (
            f"Reply endorses suspicious URL(s) as official/legitimate: "
            f"{', '.join(flagged_urls)}"
        )
        logger.error(f"🚨 OUTPUT BLOCKED: {reason}")
        return False, reason

    # Check: does the reply contain a blocked URL?
    blocked_in_reply = [u for u in reply_urls if is_blocklisted(u)]
    if blocked_in_reply:
        reason = f"Reply contains known scam URL(s): {', '.join(blocked_in_reply)}"
        logger.error(f"🚨 OUTPUT BLOCKED: {reason}")
        return False, reason

    return True, "ok"


def get_scam_warning_reply(suspicious_urls: List[str] = None, blocked_urls: List[str] = None) -> str:
    """
    Generate a safe fallback reply when the bot detects a scam.
    """
    if blocked_urls:
        return (
            "That link is a known phishing/scam site. It is NOT affiliated with Venice AI. "
            "The only official Venice domain is venice.ai — never connect your wallet "
            "or enter credentials on unverified sites."
        )
    if suspicious_urls:
        return (
            "I can't verify that link as official Venice AI. "
            "The only official domain is venice.ai — be cautious with any site "
            "asking you to connect a wallet or enter credentials."
        )
    return (
        "I detected something potentially unsafe in this context. "
        "For anything Venice AI related, only trust venice.ai as the official domain."
    )


# ═════════════════════════════════════════════════════════════════
# CENSORSHIP DETECTION
# ═════════════════════════════════════════════════════════════════
# Detects when a model refuses/self-censors so we can retry with
# the uncensored fallback (GLM Heretic).

# Phrases that indicate the model is refusing to answer
_REFUSAL_PATTERNS = [
    # Direct refusals
    r"I (?:can't|cannot|won't|will not|am unable to|'m not able to) (?:help|assist|provide|generate|create|write|respond|answer|discuss|engage)",
    r"I (?:must|have to|need to) (?:decline|refuse|refrain)",
    r"I'?m sorry,? (?:but )?I (?:can't|cannot|won't)",
    r"I (?:don't|do not) (?:feel comfortable|think it'?s appropriate)",
    # Policy / guidelines
    r"(?:against|violates?|outside) (?:my |the )?(?:guidelines|policies|terms|rules|ethical)",
    r"(?:content|usage) (?:policy|policies|guidelines)",
    r"as an AI (?:language )?model",
    r"as a (?:responsible|helpful) AI",
    r"my (?:programming|training|guidelines) (?:prevents?|doesn'?t allow)",
    # Safety theater
    r"(?:could|might|may) (?:be )?(?:harmful|dangerous|offensive|inappropriate|unethical)",
    r"I'?m (?:designed|programmed|trained) to (?:be safe|avoid|not)",
    r"(?:promote|encourage|endorse|glorify|facilitate) (?:harmful|illegal|dangerous|violence)",
    r"(?:sensitive|controversial|inappropriate) (?:topic|subject|content|material)",
    # Deflections
    r"I(?:'d| would) (?:encourage|suggest|recommend) (?:you |that you )?(?:consult|speak|talk|reach out)",
    r"please (?:consult|contact|reach out to|speak with) a (?:professional|qualified|licensed)",
    r"(?:seek|get) (?:professional|medical|legal|qualified) (?:help|advice|assistance|guidance)",
    # Moralizing filler
    r"it'?s important to (?:note|remember|consider|understand) that",
    r"I want to (?:emphasize|stress|remind|be clear) that",
    r"while I understand (?:your|the) (?:question|interest|curiosity)",
]
_REFUSAL_RE = re.compile("|".join(_REFUSAL_PATTERNS), re.IGNORECASE)

# Short non-answers that are essentially refusals
_EMPTY_REFUSALS = [
    "I can't help with that.",
    "I'm not able to assist with this request.",
    "I cannot provide that information.",
    "That's not something I can help with.",
]


def is_censored(text: Optional[str]) -> bool:
    """
    Detect if model output looks like a refusal/self-censorship.
    Returns True if the response appears censored and should be retried
    with the uncensored model.

    Heuristics:
    1. Matches known refusal phrases (regex)
    2. Response is suspiciously short + contains refusal language
    3. Response is an exact match for common canned refusals
    """
    if not text:
        return False

    text = text.strip()

    # Exact match for canned non-answers
    if text in _EMPTY_REFUSALS:
        logger.info(f"🔓 Censorship detected (canned refusal): {text[:80]}")
        return True

    # Regex pattern match
    match = _REFUSAL_RE.search(text)
    if match:
        # For longer responses, only flag if the refusal is at the start
        # (some models refuse first, then answer anyway — that's fine)
        if len(text) < 300 or match.start() < 100:
            logger.info(f"🔓 Censorship detected (pattern '{match.group()}'): {text[:120]}…")
            return True

    # Very short response that smells like a dodge
    if len(text) < 60 and any(
        phrase in text.lower()
        for phrase in ("i can't", "i cannot", "i won't", "not appropriate", "not able")
    ):
        logger.info(f"🔓 Censorship detected (short refusal): {text}")
        return True

    return False
