"""Clean, human-readable ReAct trace (dev/testing).

Replaces the workflow's noisy `workflows.verbose` object dumps. render_event()
maps the agent's streamed events to tidy lines:

    💭 Thought: ...        (the model's reasoning for a step)
    🔧 Action: Tool(arg)   (which tool it chose + input)
    📤 Observation: ...     (what the tool returned, truncated)

Retrieval sources (with scores) are logged separately by
agent.observability.RetrievalLogger. All lines go through the "agent.trace"
logger, which main_agent configures with a minimal (timestamp-free) format.
"""
import logging

logger = logging.getLogger("agent.trace")

_MAX_OBS = 200
_MAX_THOUGHT = 240


def _message_text(msg) -> str:
    parts = []
    for block in getattr(msg, "blocks", None) or []:
        text = getattr(block, "text", None) or getattr(block, "content", None)
        if text:
            parts.append(str(text))
    return "\n".join(parts).strip()


def _extract_thought(text: str) -> str:
    """Pull just the 'Thought:' portion out of a ReAct step (best-effort)."""
    if "Thought:" in text:
        seg = text.split("Thought:", 1)[1]
        for stop in ("Action:", "Answer:"):
            if stop in seg:
                seg = seg.split(stop, 1)[0]
        return seg.strip()
    return text.strip()


def _truncate(text: str, limit: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit] + "…"


def render_event(ev) -> None:
    """Print one event of the ReAct trace, if it's a meaningful step."""
    from llama_index.core.agent.workflow import ToolCall, ToolCallResult, AgentOutput

    if isinstance(ev, ToolCall):
        kwargs = ev.tool_kwargs or {}
        arg = kwargs.get("query") or kwargs.get("input") or (
            next(iter(kwargs.values())) if kwargs else ""
        )
        logger.info("🔧 Action: %s(%r)", ev.tool_name, arg)

    elif isinstance(ev, ToolCallResult):
        logger.info("📤 Observation: %s", _truncate(str(ev.tool_output), _MAX_OBS))

    elif isinstance(ev, AgentOutput):
        # AgentOutput with tool_calls = a reasoning step (has a Thought);
        # without = the final answer (main_agent prints that separately).
        if ev.tool_calls and ev.response is not None:
            thought = _extract_thought(_message_text(ev.response))
            if thought:
                logger.info("💭 Thought: %s", _truncate(thought, _MAX_THOUGHT))
