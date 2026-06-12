"""FAQ retrieval and model-summary formatting.

These run against the committed snapshots (venice_faqs.json, venice_models.json),
so they stay offline and deterministic. The summary test uses the snapshot loader
directly rather than get_models(), which would otherwise hit the live API.
"""
from venice_knowledge import relevant_faqs, summarize_models, _load_models_snapshot


def test_relevant_faqs_surfaces_accurate_diem_answer():
    hits = relevant_faqs("what is diem and can I trade it?")
    joined = "\n".join(hits).lower()

    assert len(hits) >= 1, "expected at least one FAQ hit"
    assert "erc-20" in joined or "tokenized compute" in joined
    # DIEM IS transferable — the snapshot must not carry the old wrong claim.
    assert "non-transferable" not in joined


def test_summarize_models_formats_snapshot():
    models = _load_models_snapshot()
    assert isinstance(models, list) and len(models) > 0
    assert all(m.get("id") for m in models)

    summary = summarize_models(models)
    assert isinstance(summary, str) and summary
    assert "ctx" in summary and "type=" in summary
