"""REST endpoints for the OpenRouter agentic loop.

  * ``POST /agent/chat``      — single or multi-turn chat with optional tool use
  * ``POST /agent/stream``    — streaming single-step chat (SSE)
  * ``GET  /agent/history``   — per-session conversation history
  * ``DELETE /agent/history`` — clear session history
  * ``GET  /agent/tools``     — list registered built-in security tools

Sessions are keyed by the authenticated user's ID so each user gets an
isolated conversation history. Agents are lazily constructed and cached
for the lifetime of the process.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from raven.auth.dependencies import current_user, require_operator
from raven.auth.models import User
from raven.config import settings

log = logging.getLogger(__name__)

router = APIRouter(prefix="/agent", tags=["agent"])

# -- per-user agent cache -----------------------------------------------
_agents: Dict[str, Any] = {}
_agents_lock = threading.Lock()


def _get_agent(user_id: str):
    """Return (or create) the OpenRouterAgent for *user_id*."""
    with _agents_lock:
        if user_id not in _agents:
            from raven.ai.openrouter_agent import OpenRouterAgent
            agent = OpenRouterAgent(
                api_key=settings.ai_api_key,
                model=settings.ai_model or "openrouter/auto",
                instructions=(
                    "You are Project Raven, an advanced AI security analyst. "
                    "Use available tools to investigate targets, search exploits, "
                    "and provide actionable threat intelligence."
                ),
                temperature=settings.ai_temperature,
                max_tokens=settings.ai_max_tokens,
                timeout=settings.ai_timeout,
                http_referer=settings.openrouter_http_referer,
                app_title=settings.openrouter_title,
            )
            agent.register_security_defaults()
            _agents[user_id] = agent
        return _agents[user_id]


# -- request / response models ------------------------------------------

class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=32_000)
    clear_history: bool = False


class ChatResponse(BaseModel):
    content: str
    steps: int
    model: str
    session_messages: int


class HistoryItem(BaseModel):
    role: str
    content: str


# -- endpoints ----------------------------------------------------------

@router.post("/chat", response_model=ChatResponse)
async def agent_chat(
    req: ChatRequest,
    user: User = Depends(require_operator),
):
    """Run a multi-step agent turn with full tool use.

    Requires ``operator`` role. Each user has an isolated conversation
    history that persists across calls until explicitly cleared.
    """
    agent = _get_agent(str(user.id))

    if req.clear_history:
        agent.clear_history()

    try:
        result = agent.send(req.message)
    except Exception as exc:
        log.error("Agent error for user %s: %s", user.id, exc)
        raise HTTPException(status_code=502, detail=f"Agent error: {exc}")

    return ChatResponse(
        content=result.content,
        steps=result.steps,
        model=result.model,
        session_messages=len(result.messages),
    )


@router.post("/stream")
async def agent_stream(
    req: ChatRequest,
    user: User = Depends(require_operator),
):
    """Stream a single-step response (no tool calls) as Server-Sent Events."""
    agent = _get_agent(str(user.id))

    if req.clear_history:
        agent.clear_history()

    def _event_generator():
        try:
            for delta in agent.send_stream(req.message):
                safe = delta.replace("\n", "\\n")
                yield f"data: {safe}\n\n"
        except Exception as exc:
            yield f"event: error\ndata: {exc}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(_event_generator(), media_type="text/event-stream")


@router.get("/history", response_model=List[HistoryItem])
async def agent_history(user: User = Depends(current_user)):
    """Return the current session's conversation history."""
    agent = _get_agent(str(user.id))
    return [
        HistoryItem(role=m.role, content=m.content)
        for m in agent.get_messages()
    ]


@router.delete("/history")
async def clear_agent_history(user: User = Depends(current_user)):
    """Clear the current session's conversation history."""
    agent = _get_agent(str(user.id))
    agent.clear_history()
    return {"cleared": True}


@router.get("/tools")
async def list_agent_tools(user: User = Depends(current_user)):
    """List all tools registered in the security agent."""
    agent = _get_agent(str(user.id))
    return {
        "tools": [
            {
                "name": t.name,
                "description": t.description,
                "parameters": t.parameters,
            }
            for t in agent._tools.values()
        ]
    }
