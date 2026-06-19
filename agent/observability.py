"""Dev/testing observability for the agent.

RetrievalLogger surfaces which knowledge-base chunks the RAG step pulled (id,
category, similarity score, snippet) — the equivalent of inspecting
response.source_nodes. Wire it via Settings.callback_manager when running
verbose; it's a no-op otherwise.
"""
import logging

from llama_index.core.callbacks.base_handler import BaseCallbackHandler
from llama_index.core.callbacks.schema import CBEventType, EventPayload

logger = logging.getLogger("agent.trace")


class RetrievalLogger(BaseCallbackHandler):
    def __init__(self):
        super().__init__(event_starts_to_ignore=[], event_ends_to_ignore=[])

    def start_trace(self, trace_id=None):
        pass

    def end_trace(self, trace_id=None, trace_map=None):
        pass

    def on_event_start(self, event_type, payload=None, event_id="", parent_id="", **kwargs):
        return event_id

    def on_event_end(self, event_type, payload=None, event_id="", **kwargs):
        if event_type != CBEventType.RETRIEVE or not payload:
            return
        nodes = payload.get(EventPayload.NODES) or []
        logger.info("RAG retrieved %d chunk(s):", len(nodes))
        for i, ns in enumerate(nodes, 1):
            meta = getattr(ns.node, "metadata", {}) or {}
            snippet = ns.node.get_content()[:90].replace("\n", " ")
            logger.info(
                "  [%d] score=%.3f cat=%r id=%r :: %s",
                i, ns.score or 0.0, meta.get("category", ""), meta.get("id", ""), snippet,
            )
