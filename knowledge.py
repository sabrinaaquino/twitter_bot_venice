"""Shared knowledge platform — RAG over the Venice FAQ.

A foundational, agent-agnostic component for the (future) multi-agent team. Two
layers, so each agent can use the shape it needs without locking the others in:

    retrieve(query) -> list[dict]      # low-level source chunks (cheap, flexible)
    answer(query, llm) -> str          # synthesized answer (stable, simple)

answer() is built on retrieve(). Sophisticated agents (Twitter, Discord,
marketing) should prefer retrieve() and synthesize for their own medium — cheaper
and better grounded. Simple/legacy callers can keep using answer() without
knowing anything about retrieval. Keep BOTH signatures stable: consumers depend
on them.

The index is built from the committed venice_faqs.json snapshot and persisted to
Config.KNOWLEDGE_STORAGE_DIR (load-if-present). Designed to also ingest
markdown/PDF docs later via SimpleDirectoryReader.
"""
import json
import os

from config import Config
from embeddings import get_embed_model

_DIR = os.path.dirname(os.path.abspath(__file__))
_FAQ_PATH = os.path.join(_DIR, Config.VENICE_FAQ_FILE)


def _faq_documents():
    """Turn the FAQ snapshot (en locale) into LlamaIndex Documents (one per Q/A)."""
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

    embed_model = embed_model or get_embed_model()
    sdir = storage_dir or Config.KNOWLEDGE_STORAGE_DIR

    if os.path.isdir(sdir) and os.listdir(sdir):
        sc = StorageContext.from_defaults(persist_dir=sdir)
        return load_index_from_storage(sc, embed_model=embed_model)

    docs = documents if documents is not None else _faq_documents()
    index = VectorStoreIndex.from_documents(docs, embed_model=embed_model)
    index.storage_context.persist(persist_dir=sdir)
    return index


def retrieve(query, top_k=4, embed_model=None, storage_dir=None) -> list[dict]:
    """Low-level: return the most relevant FAQ chunks as plain dicts.

    Returns [{"text", "score", "category", "id"}], decoupled from LlamaIndex node
    types so any consumer (incl. non-Python / future Supabase-backed agents) can
    use them. This is the API new agents should build on.
    """
    retriever = get_index(embed_model, storage_dir).as_retriever(similarity_top_k=top_k)
    nodes = retriever.retrieve(query)
    out = []
    for ns in nodes:
        meta = getattr(ns.node, "metadata", {}) or {}
        out.append({
            "text": ns.node.get_content(),
            "score": float(ns.score or 0.0),
            "category": meta.get("category", ""),
            "id": meta.get("id", ""),
        })
    return out


def answer(query, llm, top_k=4, embed_model=None, storage_dir=None) -> str:
    """Stable, simple: retrieve + synthesize a single answer string.

    Built on retrieve(). For simple/legacy callers that don't want to handle
    chunks themselves. Keep this signature stable.
    """
    query_engine = get_index(embed_model, storage_dir).as_query_engine(
        llm=llm, similarity_top_k=top_k,
    )
    return str(query_engine.query(query)).strip()
