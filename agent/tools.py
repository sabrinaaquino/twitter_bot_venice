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


def knowledge_lookup(query: str, embed_model=None, storage_dir=None) -> str:
    """Return the most relevant Venice-FAQ source snippets for `query`.

    Backend chosen by Config.KNOWLEDGE_BACKEND:
      - "keyword" (default): legacy venice_knowledge.relevant_faqs scorer — no
        embeddings, no index. Right-sized for the small (~90 Q&A) FAQ.
      - "vector": semantic retrieval via the shared knowledge.retrieve() (needs an
        embedding model; opt-in, heavier deps).
    Either way the agent synthesizes the final answer from these snippets.
    """
    if Config.KNOWLEDGE_BACKEND == "vector":
        from knowledge import retrieve
        chunks = retrieve(query, embed_model=embed_model, storage_dir=storage_dir)
        if not chunks:
            return "No matching Venice facts found."
        return "\n\n".join(
            f"[{i}] ({c['category']}) {c['text']}" for i, c in enumerate(chunks, 1)
        )

    # default: keyword (legacy) — dependency-free FAQ lookup
    from venice_knowledge import relevant_faqs
    faqs = relevant_faqs(query, limit=4)
    if not faqs:
        return "No matching Venice facts found."
    return "\n\n".join(f"[{i}] {qa}" for i, qa in enumerate(faqs, 1))


def knowledge_retrieve_tool(embed_model=None, storage_dir=None) -> FunctionTool:
    """Knowledge-base lookup that returns SOURCE snippets (not a pre-synthesized
    answer) — the agent synthesizes once in its own final turn. Backend is set by
    Config.KNOWLEDGE_BACKEND (keyword default / vector opt-in); see knowledge_lookup."""
    def venice_knowledge_search(query: str) -> str:
        """Look up authoritative Venice facts from the official FAQ: VVV/sVVV/DIEM
        tokenomics, staking, plans/pricing, models, API. Returns the most relevant
        source snippets — base your answer on them, preferring them over memory."""
        return knowledge_lookup(query, embed_model=embed_model, storage_dir=storage_dir)

    return FunctionTool.from_defaults(fn=venice_knowledge_search, name="Venice_Knowledge_Base")


def venice_search_tool() -> FunctionTool:
    return FunctionTool.from_defaults(fn=_venice_web_search, name="Venice_Web_Search")


def note_saver_tool() -> FunctionTool:
    return FunctionTool.from_defaults(fn=_save_note, name="Note_Saver")
