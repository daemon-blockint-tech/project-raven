"""REST endpoints for the external security-tool layer.

  * ``GET /tools``                — availability matrix
  * ``GET /tools/mcp``            — list registered MCP servers
  * ``POST /tools/{name}/run``    — invoke a tool (operator-gated, audit-logged)

The execution endpoint delegates to per-tool adapter methods discovered at
call time; the body shape is ``{method: str, kwargs: {...}}`` so the route
stays small and uniform across the whole catalogue.
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from raven.auth.dependencies import current_user, require_admin, require_operator
from raven.auth.models import User
from raven.tools.mcp_registry import registry as mcp_registry


router = APIRouter(prefix="/tools", tags=["tools"])


# --- Adapter discovery map ---------------------------------------------

def _load_adapters() -> Dict[str, str]:
    """Map ``name → module:class`` for tool-name resolution."""
    return {
        "subfinder": "raven.tools.projectdiscovery:SubfinderAdapter",
        "naabu":     "raven.tools.projectdiscovery:NaabuAdapter",
        "httpx":     "raven.tools.projectdiscovery:HttpxAdapter",
        "interactsh":"raven.tools.projectdiscovery:InteractshAdapter",
        "exploitdb": "raven.tools.exploitdb:SearchsploitAdapter",
        "recon_ng":  "raven.tools.recon_ng:ReconNgAdapter",
        "yara":      "raven.tools.yara_scan:YaraScanner",
        "jadx":      "raven.tools.jadx:JadxAdapter",
        "radare2":   "raven.tools.radare2:Radare2Adapter",
        "frida":     "raven.tools.frida:FridaAdapter",
        "volatility":"raven.tools.volatility:VolatilityAdapter",
        "cyberchef": "raven.tools.cyberchef:CyberchefAdapter",
    }


def _resolve(name: str):
    spec = _load_adapters().get(name)
    if spec is None:
        raise HTTPException(status_code=404, detail=f"unknown tool: {name!r}")
    module_path, class_name = spec.split(":")
    import importlib
    module = importlib.import_module(module_path)
    return getattr(module, class_name)


# --- Endpoints ---------------------------------------------------------

@router.get("")
async def list_tools(user: User = Depends(current_user)):
    """Availability matrix of every registered adapter."""
    out: Dict[str, Dict[str, Any]] = {}
    for name in _load_adapters():
        try:
            cls = _resolve(name)
            instance = cls()
            out[name] = {
                "tool_name": getattr(instance, "tool_name", name),
                "available": bool(instance.is_available()),
                "install_hint": getattr(instance, "install_hint", ""),
            }
        except Exception as exc:
            out[name] = {"tool_name": name, "available": False, "error": str(exc)}
    return out


@router.get("/mcp")
async def list_mcp(user: User = Depends(current_user)):
    """Return the registered MCP servers + capability index."""
    reg = mcp_registry()
    return {
        "servers": [s.to_dict() for s in reg.list()],
        "capabilities": sorted({c for s in reg.list() for c in s.capabilities}),
    }


class ToolRunRequest(BaseModel):
    method: str = Field(..., min_length=1, max_length=64)
    kwargs: Dict[str, Any] = Field(default_factory=dict)


@router.post("/{name}/run")
async def run_tool(
    name: str,
    payload: ToolRunRequest,
    user: User = Depends(require_operator),
):
    """Invoke ``name.method(**kwargs)`` and return the structured result.

    Operator role required; every call is recorded by the audit middleware.
    """
    cls = _resolve(name)
    instance = cls()
    method = getattr(instance, payload.method, None)
    if method is None or not callable(method):
        raise HTTPException(
            status_code=400,
            detail=f"{name!r} has no callable method {payload.method!r}",
        )
    if payload.method.startswith("_"):
        raise HTTPException(status_code=400, detail="private methods not callable")
    try:
        result = method(**payload.kwargs)
    except TypeError as exc:
        raise HTTPException(status_code=400, detail=f"bad arguments: {exc}")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"tool error: {exc}")

    if hasattr(result, "to_dict"):
        return result.to_dict()
    return {"result": result}
