"""Small helpers — URL extraction, etc."""
import re
from typing import List, Optional

_URL_RE = re.compile(r"https?://[^\s)]+", re.IGNORECASE)


def extract_urls_from_entities(entities: Optional[dict]) -> List[str]:
    if not entities:
        return []
    urls = []
    for u in entities.get("urls", []):
        expanded = u.get("unwound_url") or u.get("expanded_url") or u.get("url")
        if expanded and isinstance(expanded, str):
            urls.append(expanded)
    return list(dict.fromkeys(urls))


def extract_urls_from_text(text: Optional[str]) -> List[str]:
    if not text:
        return []
    return list(dict.fromkeys(_URL_RE.findall(text)))
