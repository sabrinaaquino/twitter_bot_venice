"""Shared knowledge platform — retrieve()/answer()/get_index (offline, stubbed)."""
from typing import List

import pytest

from knowledge import get_index, retrieve, answer


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
            v = [0.0] * 8
            for i, ch in enumerate(text):
                v[i % 8] += (ord(ch) % 17) / 17.0
            return v

    return _Stub()


def _docs():
    from llama_index.core import Document
    return [
        Document(text="Q: What is DIEM?\nA: A tokenized compute unit on Base.",
                 metadata={"category": "Token", "id": "faq-diem"}),
        Document(text="Q: What is VVV?\nA: Venice's utility token; stake for sVVV.",
                 metadata={"category": "Token", "id": "faq-vvv"}),
    ]


def test_build_persists_then_loads(tmp_path):
    import os
    sdir = str(tmp_path / "storage")
    embed = _stub_embedding()
    idx1 = get_index(embed_model=embed, storage_dir=sdir, documents=_docs())
    assert idx1 is not None
    assert os.path.isdir(sdir) and os.listdir(sdir)
    idx2 = get_index(embed_model=embed, storage_dir=sdir, documents=None)  # load branch
    assert idx2 is not None


def test_retrieve_returns_chunk_dicts(tmp_path):
    sdir = str(tmp_path / "storage")
    get_index(embed_model=_stub_embedding(), storage_dir=sdir, documents=_docs())
    chunks = retrieve("what is diem?", top_k=2, embed_model=_stub_embedding(), storage_dir=sdir)
    assert isinstance(chunks, list) and len(chunks) >= 1
    c = chunks[0]
    assert set(c) == {"text", "score", "category", "id"}
    assert isinstance(c["text"], str) and isinstance(c["score"], float)


def test_answer_returns_string(tmp_path):
    from llama_index.core.llms import MockLLM
    sdir = str(tmp_path / "storage")
    get_index(embed_model=_stub_embedding(), storage_dir=sdir, documents=_docs())
    out = answer("what is diem?", llm=MockLLM(),
                 embed_model=_stub_embedding(), storage_dir=sdir)
    assert isinstance(out, str) and out
