"""LLM security gate — offline (Venice call stubbed). Verdict parsing + fail-open."""
from agent.security_filter import llm_should_respond


def test_stop_blocks(monkeypatch):
    monkeypatch.setattr("venice_api._call_venice", lambda *a, **k: "STOP")
    assert llm_should_respond("launch $X on base") is False


def test_respond_allows(monkeypatch):
    monkeypatch.setattr("venice_api._call_venice", lambda *a, **k: "RESPOND")
    assert llm_should_respond("what is DIEM?") is True


def test_fail_open_on_none(monkeypatch):
    # Venice returned nothing (its _call_venice swallows errors → None) → RESPOND.
    monkeypatch.setattr("venice_api._call_venice", lambda *a, **k: None)
    assert llm_should_respond("anything") is True


def test_fail_open_on_exception(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("venice down")
    monkeypatch.setattr("venice_api._call_venice", boom)
    assert llm_should_respond("anything") is True


def test_stop_with_trailing_text(monkeypatch):
    monkeypatch.setattr("venice_api._call_venice", lambda *a, **k: "STOP - looks like spam")
    assert llm_should_respond("spammy") is False


def test_defensive_parse_does_not_stop_on_respond_mentioning_stop(monkeypatch):
    monkeypatch.setattr("venice_api._call_venice", lambda *a, **k: "RESPOND — no reason to stop")
    assert llm_should_respond("legit question") is True


# ── JSON verdict (preferred path) ─────────────────────────────────

def test_json_stop(monkeypatch):
    monkeypatch.setattr("venice_api._call_venice",
                        lambda *a, **k: '{"verdict": "STOP", "reason": "launch command"}')
    assert llm_should_respond("launch $X on base") is False


def test_json_respond(monkeypatch):
    monkeypatch.setattr("venice_api._call_venice",
                        lambda *a, **k: '{"verdict": "RESPOND", "reason": "genuine question"}')
    assert llm_should_respond("what is DIEM?") is True


def test_json_in_code_fence(monkeypatch):
    monkeypatch.setattr("venice_api._call_venice",
                        lambda *a, **k: '```json\n{"verdict": "STOP", "reason": "spam"}\n```')
    assert llm_should_respond("airdrop claim") is False


def test_malformed_json_falls_back_to_text(monkeypatch):
    monkeypatch.setattr("venice_api._call_venice", lambda *a, **k: '{bad json... STOP')
    assert llm_should_respond("spammy") is False


def test_no_clear_verdict_fails_open(monkeypatch):
    monkeypatch.setattr("venice_api._call_venice", lambda *a, **k: "hmm, not sure")
    assert llm_should_respond("ambiguous") is True


def test_falls_back_to_primary_model_when_small_model_fails(monkeypatch):
    from config import Config
    calls = []
    def stub(model, system, content, *a, **k):
        calls.append(model)
        if model == Config.SECURITY_FILTER_MODEL:
            return None                       # small model unavailable
        return '{"verdict": "STOP", "reason": "launch command"}'   # primary works
    monkeypatch.setattr("venice_api._call_venice", stub)
    assert llm_should_respond("launch $X on base") is False
    assert calls == [Config.SECURITY_FILTER_MODEL, Config.AGENT_MODEL]


def test_fail_open_only_when_all_models_fail(monkeypatch):
    from config import Config
    calls = []
    def stub(model, *a, **k):
        calls.append(model)
        return None                            # every model fails
    monkeypatch.setattr("venice_api._call_venice", stub)
    assert llm_should_respond("anything") is True
    assert calls == [Config.SECURITY_FILTER_MODEL, Config.AGENT_MODEL]


def test_requests_json_response_format(monkeypatch):
    seen = {}
    def spy(model, system, content, *a, **k):
        seen["response_format"] = k.get("response_format")
        return '{"verdict": "RESPOND"}'
    monkeypatch.setattr("venice_api._call_venice", spy)
    llm_should_respond("hi")
    assert seen["response_format"] == {"type": "json_object"}
