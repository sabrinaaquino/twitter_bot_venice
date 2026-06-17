"""Agent FunctionTools — offline (Venice call stubbed)."""
import sys
import types

import pytest

from config import Config
from agent.tools import venice_search_tool, note_saver_tool
from agent import tools as tools_mod


def test_note_saver_appends_to_notes_file(tmp_path, monkeypatch):
    notes = tmp_path / "notes.txt"
    monkeypatch.setattr(Config, "NOTES_FILE", str(notes))
    tools_mod._save_note("VVV trending after staking update")
    tools_mod._save_note("DIEM mint rate questions spiking")
    lines = notes.read_text(encoding="utf-8").splitlines()
    assert lines == ["VVV trending after staking update", "DIEM mint rate questions spiking"]


def test_web_search_tool_uses_venice_call(monkeypatch):
    monkeypatch.setattr("venice_api._call_venice", lambda *a, **k: "BTC is $100k.")
    assert tools_mod._venice_web_search("btc price?") == "BTC is $100k."


def test_web_search_handles_empty_result(monkeypatch):
    monkeypatch.setattr("venice_api._call_venice", lambda *a, **k: None)
    assert "No live results" in tools_mod._venice_web_search("anything")


def test_tool_names():
    assert venice_search_tool().metadata.name == "Venice_Web_Search"
    assert note_saver_tool().metadata.name == "Note_Saver"


def test_knowledge_lookup_keyword_is_default(monkeypatch):
    # Default backend is keyword → legacy relevant_faqs, never touches embeddings.
    monkeypatch.setattr(Config, "KNOWLEDGE_BACKEND", "keyword")
    import venice_knowledge
    monkeypatch.setattr(venice_knowledge, "relevant_faqs",
                        lambda q, limit=4: ["Q: What is DIEM?\nA: a tokenized compute unit"])
    # guard: the vector path must NOT be taken (would import/raise)
    boom = types.ModuleType("knowledge")
    def _boom(*a, **k):
        raise AssertionError("vector retrieve used in keyword mode")
    boom.retrieve = _boom
    monkeypatch.setitem(sys.modules, "knowledge", boom)
    out = tools_mod.knowledge_lookup("what is diem?")
    assert "DIEM" in out and "compute unit" in out


def test_knowledge_lookup_keyword_handles_empty(monkeypatch):
    monkeypatch.setattr(Config, "KNOWLEDGE_BACKEND", "keyword")
    import venice_knowledge
    monkeypatch.setattr(venice_knowledge, "relevant_faqs", lambda q, limit=4: [])
    assert "No matching" in tools_mod.knowledge_lookup("nonsense")


def test_knowledge_lookup_vector_when_enabled(monkeypatch):
    # Opt-in vector path → knowledge.retrieve, formatted with category tags.
    monkeypatch.setattr(Config, "KNOWLEDGE_BACKEND", "vector")
    fake = types.ModuleType("knowledge")
    fake.retrieve = lambda q, embed_model=None, storage_dir=None: [
        {"text": "Stake VVV for API credits", "score": 0.9, "category": "Token", "id": "faq-vvv"},
    ]
    monkeypatch.setitem(sys.modules, "knowledge", fake)
    out = tools_mod.knowledge_lookup("vvv?")
    assert "[1] (Token)" in out and "Stake VVV for API credits" in out


def test_knowledge_tool_wraps_lookup_with_name(monkeypatch):
    from agent.tools import knowledge_retrieve_tool
    monkeypatch.setattr(tools_mod, "knowledge_lookup", lambda q, **k: f"LOOKUP:{q}")
    tool = knowledge_retrieve_tool()
    assert tool.metadata.name == "Venice_Knowledge_Base"
    assert tool.fn("hi") == "LOOKUP:hi"
