"""Agent tools (FunctionTools).

- Venice_Web_Search: live web results, reusing the proven venice_api._call_venice
  raw path with web search forced ON.
- Note_Saver: appends a social-listening observation to Config.NOTES_FILE
  (placeholder for the future Social-to-SEO pipeline).

The docstrings ARE the tool descriptions the ReAct loop reasons over — keep them
specific so the model picks the right tool.
"""
from llama_index.core.tools import FunctionTool

from config import Config


def _venice_web_search(query: str) -> str:
    """Search the live web via Venice for current, time-sensitive facts (prices,
    news, recent events). Returns a concise factual summary. Do NOT use for
    general knowledge or Venice-FAQ questions."""
    from venice_api import _call_venice
    out = _call_venice(
        Config.MODEL_PRIMARY,
        "Answer factually and concisely using live web results.",
        query,
        force_search=True,
    )
    return out or "No live results available."


def _save_note(observation: str) -> str:
    """Save a short note about a noteworthy or viral social trend you observed,
    for later analysis. Returns a confirmation string."""
    with open(Config.NOTES_FILE, "a", encoding="utf-8") as f:
        f.write(observation.strip() + "\n")
    return "Saved."


def venice_search_tool() -> FunctionTool:
    return FunctionTool.from_defaults(fn=_venice_web_search, name="Venice_Web_Search")


def note_saver_tool() -> FunctionTool:
    return FunctionTool.from_defaults(fn=_save_note, name="Note_Saver")
