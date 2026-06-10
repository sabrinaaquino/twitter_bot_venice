"""Venice LLM for the ReAct reasoning loop, via LlamaIndex's OpenAILike.

Venice is OpenAI-compatible (api.venice.ai/api/v1). Its models advertise no
function-calling, so is_function_calling_model=False forces the text-based ReAct
loop. The reasoning LLM runs with web search OFF (cheap, deterministic turns);
live web search is a dedicated tool (agent.tools.venice_search_tool).
"""
from llama_index.llms.openai_like import OpenAILike

from config import Config

VENICE_API_BASE = "https://api.venice.ai/api/v1"


def reasoning_llm() -> OpenAILike:
    return OpenAILike(
        model=Config.AGENT_MODEL,
        api_base=VENICE_API_BASE,
        api_key=Config.VENICE_API_KEY,
        is_chat_model=True,
        is_function_calling_model=False,   # → text-based ReAct loop
        context_window=Config.AGENT_CONTEXT_WINDOW,
        timeout=Config.VENICE_REQUEST_TIMEOUT_SECONDS,
        temperature=0.6,
        # Venice's non-standard params must ride in the OpenAI SDK's `extra_body`
        # (a bare top-level kwarg is rejected by AsyncCompletions.create). Web
        # search OFF here so reasoning turns stay cheap; the search tool turns it
        # on deliberately via the raw venice_api path.
        additional_kwargs={
            "extra_body": {
                "venice_parameters": {
                    "enable_web_search": "off",
                    "enable_web_scraping": False,
                    "enable_web_citations": False,
                    "include_venice_system_prompt": False,
                }
            }
        },
    )
