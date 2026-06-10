"""Embedding model for the RAG knowledge index.

"venice" → Venice's OpenAI-compatible embeddings (production).
"local"  → a local HuggingFace model (dev default), because the Venice account
           currently returns HTTP 402 (no credits) so live embeddings fail.

NOTE: the persisted index in Config.KNOWLEDGE_STORAGE_DIR is specific to whichever
embedding model built it — switching EMBED_BACKEND requires rebuilding it.
"""
from config import Config

VENICE_API_BASE = "https://api.venice.ai/api/v1"


def get_embed_model():
    if Config.EMBED_BACKEND == "venice":
        from llama_index.embeddings.openai_like import OpenAILikeEmbedding
        return OpenAILikeEmbedding(
            model_name=Config.EMBED_MODEL_VENICE,
            api_base=VENICE_API_BASE,
            api_key=Config.VENICE_API_KEY,
            embed_batch_size=10,
        )

    # Dev default: embed locally (no network, dodges the 402).
    try:
        from llama_index.embeddings.huggingface import HuggingFaceEmbedding
    except ImportError as e:  # heavy, optional dep
        raise ImportError(
            "Local embeddings need 'llama-index-embeddings-huggingface'. Install it "
            "(pip install llama-index-embeddings-huggingface) or set EMBED_BACKEND=venice."
        ) from e
    return HuggingFaceEmbedding(model_name=Config.EMBED_MODEL_LOCAL)
