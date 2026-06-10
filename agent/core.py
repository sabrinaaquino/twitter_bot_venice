"""ReAct agent construction and a single-query run.

build_agent() wires the Venice reasoning LLM, the knowledge-base query tool, the
web-search tool, and the note-saver under the agent system prompt. run_agent()
assembles the user message (mirroring venice_api.analyse's context handling),
injects the URL-safety context, and runs one turn of the ReAct loop.

The guardrail (agent.guardrails) is what enforces safety around this; nothing
here posts anything.
"""
from datetime import datetime, timezone

from config import Config
from safety import build_url_safety_context


def time_context(now: datetime) -> str:
    """Ambient time awareness for the agent so it doesn't guess the date.

    UTC + day-of-week + time-of-day. UTC (not 'local') because a tweet doesn't
    reliably tell us the user's timezone — better an accurate UTC than a
    confidently-wrong local time.
    """
    h = now.hour
    if 5 <= h < 12:
        tod = "morning"
    elif 12 <= h < 17:
        tod = "afternoon"
    elif 17 <= h < 22:
        tod = "evening"
    else:
        tod = "night"
    return f"Current time: {now.strftime('%A, %Y-%m-%d %H:%M')} UTC ({tod})."


def _build_user_message(query: str, context: str | None) -> str:
    """Mirror venice_api.analyse's context/continuation framing."""
    if not context:
        return query
    if context.startswith("[CONTINUING]"):
        clean = context.replace("[CONTINUING] ", "").replace("[CONTINUING]", "")
        return f'CONTINUING CONVERSATION — Previous: "{clean}"\nUser now says: "{query}"'
    return f'CONTEXT (original tweet): "{context}"\nUser asks: "{query}"'


def build_agent(llm=None, tools=None):
    from llama_index.core.agent.workflow import ReActAgent
    from agent.llm import reasoning_llm
    from agent.tools import knowledge_retrieve_tool, venice_search_tool, note_saver_tool

    llm = llm or reasoning_llm()
    if tools is None:
        tools = [
            knowledge_retrieve_tool(),   # returns source chunks; agent synthesizes
            venice_search_tool(),
            note_saver_tool(),
        ]
    return ReActAgent(
        name="venice_mind",
        description="Replies to Twitter mentions for @venice_mind.",
        system_prompt=Config.AGENT_SYSTEM_PROMPT,
        tools=tools,
        llm=llm,
        max_iterations=Config.AGENT_MAX_ITERATIONS,
        # verbose stays off — a clean trace is rendered from streamed events
        # in run_agent() instead of the framework's noisy logger.
    )


async def run_agent(
    query: str,
    *,
    context: str | None = None,
    safe_urls=None,
    suspicious_urls=None,
    blocked_urls=None,
    agent=None,
    verbose: bool = False,
) -> str:
    """Run one ReAct turn and return the final plain-text answer.

    `agent` is injectable so the guardrail tests can pass a stub (async .run).
    When verbose, a clean Thought/Action/Observation trace is rendered from the
    agent's streamed events.
    """
    agent = agent or build_agent()

    msg = f"{time_context(datetime.now(timezone.utc))}\n\n{_build_user_message(query, context)}"
    url_ctx = build_url_safety_context(
        safe_urls or [], suspicious_urls or [], blocked_urls or [],
    )
    if url_ctx:
        msg += f"\n\n{url_ctx}"

    # Concrete tweet length budget (mirrors venice_api.analyse). char_limit() is
    # 280 by default, 25k with X Premium — so inject it at runtime, not the prompt.
    char_limit = Config.char_limit()
    msg += (
        f"\n\nHARD LIMIT: your FINAL answer is a tweet and MUST be {char_limit} "
        f"characters or fewer. Count before answering and tighten until it fits — "
        f"lead with the single most useful point, cut the rest."
    )

    handler = agent.run(user_msg=msg)
    # Real ReActAgent.run() returns a streamable handler; the test stub returns a
    # plain coroutine — only stream when the handler supports it.
    if verbose and hasattr(handler, "stream_events"):
        from agent.trace import render_event
        async for ev in handler.stream_events():
            render_event(ev)
    response = await handler
    return str(response).strip()
