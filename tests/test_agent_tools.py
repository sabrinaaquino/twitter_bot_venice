"""Agent FunctionTools — offline (Venice call stubbed)."""
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
