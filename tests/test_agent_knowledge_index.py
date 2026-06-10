"""RAG knowledge index — build, persist, load (offline, stub embedder)."""
from typing import List

import pytest

from agent.knowledge_index import get_index, knowledge_query_engine_tool


def _stub_embedding():
    from llama_index.core.base.embeddings.base import BaseEmbedding

    class _Stub(BaseEmbedding):
        def _get_query_embedding(self, query: str) -> List[float]:
            return self._vec(query)

        def _get_text_embedding(self, text: str) -> List[float]:
            return self._vec(text)

        async def _aget_query_embedding(self, query: str) -> List[float]:
            return self._vec(query)

        async def _aget_text_embedding(self, text: str) -> List[float]:
            return self._vec(text)

        @staticmethod
        def _vec(text: str) -> List[float]:
            # cheap deterministic 8-dim vector from the text's chars
            v = [0.0] * 8
            for i, ch in enumerate(text):
                v[i % 8] += (ord(ch) % 17) / 17.0
            return v

    return _Stub()


def _docs():
    from llama_index.core import Document
    return [
        Document(text="Q: What is DIEM?\nA: A tokenized compute unit on Base."),
        Document(text="Q: What is VVV?\nA: Venice's utility token; stake for sVVV."),
    ]


def test_build_persists_then_loads(tmp_path):
    sdir = str(tmp_path / "storage")
    embed = _stub_embedding()

    idx1 = get_index(embed_model=embed, storage_dir=sdir, documents=_docs())
    assert idx1 is not None
    import os
    assert os.path.isdir(sdir) and os.listdir(sdir)  # persisted

    # Second call must take the load-from-storage branch (dir non-empty).
    idx2 = get_index(embed_model=embed, storage_dir=sdir, documents=None)
    assert idx2 is not None


def test_knowledge_tool_metadata(tmp_path):
    from llama_index.core.llms import MockLLM
    sdir = str(tmp_path / "storage")
    tool = knowledge_query_engine_tool(
        llm=MockLLM(), embed_model=_stub_embedding(), storage_dir=sdir,
    )
    assert tool.metadata.name == "Venice_Knowledge_Base"
    assert "Venice" in tool.metadata.description
