"""RAG "source of truth" — a persisted VectorStoreIndex over the Venice FAQ.

Replaces the keyword scoring in venice_knowledge.relevant_faqs with semantic
retrieval, exposed to the agent as a QueryEngineTool named Venice_Knowledge_Base.
The index is built from the committed venice_faqs.json snapshot and persisted to
Config.KNOWLEDGE_STORAGE_DIR (load-if-present). Designed to also ingest
markdown/PDF docs later via SimpleDirectoryReader.
"""
import json
import os

from config import Config

_DIR = os.path.dirname(os.path.abspath(__file__))
_FAQ_PATH = os.path.join(_DIR, "..", Config.VENICE_FAQ_FILE)


def _faq_documents():
    """Turn the FAQ snapshot into LlamaIndex Documents (one per Q/A)."""
    from llama_index.core import Document

    docs = []
    try:
        with open(_FAQ_PATH, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return docs
    for c in data["locales"]["en"]["categories"]:
        for q in c.get("questions", []):
            text = f"Q: {q.get('title', '')}\nA: {q.get('markdown', '')}"
            docs.append(Document(
                text=text,
                metadata={"category": c.get("title", ""), "id": q.get("id", "")},
            ))
    # FUTURE: docs += SimpleDirectoryReader(Config.KNOWLEDGE_DOCS_DIR).load_data()
    return docs


def get_index(embed_model=None, storage_dir=None, documents=None):
    """Load the persisted index if present, else build and persist it.

    embed_model is injectable so tests can pass a deterministic stub embedder.
    """
    from llama_index.core import (
        StorageContext, VectorStoreIndex, load_index_from_storage,
    )
    from agent.embeddings import get_embed_model

    embed_model = embed_model or get_embed_model()
    sdir = storage_dir or Config.KNOWLEDGE_STORAGE_DIR

    if os.path.isdir(sdir) and os.listdir(sdir):
        sc = StorageContext.from_defaults(persist_dir=sdir)
        return load_index_from_storage(sc, embed_model=embed_model)

    docs = documents if documents is not None else _faq_documents()
    index = VectorStoreIndex.from_documents(docs, embed_model=embed_model)
    index.storage_context.persist(persist_dir=sdir)
    return index


def knowledge_query_engine_tool(llm, embed_model=None, storage_dir=None):
    """Wrap the index as a QueryEngineTool the ReAct agent can call."""
    from llama_index.core.tools import QueryEngineTool

    query_engine = get_index(embed_model, storage_dir).as_query_engine(
        llm=llm, similarity_top_k=4,
    )
    return QueryEngineTool.from_defaults(
        query_engine=query_engine,
        name="Venice_Knowledge_Base",
        description=(
            "Authoritative Venice AI facts from the official FAQ: VVV/sVVV/DIEM "
            "tokenomics, staking, plans/pricing, models, and API. Prefer this over "
            "your own memory for any Venice-specific question."
        ),
    )
