"""
Model orchestrator for multi-model LM Studio deployments.

Manages three specialist models on a memory-constrained Apple M5 (16 GB unified):

  FAST   → ibm/granite-4-micro          : JSON tasks, hypothesis gen, CVE lookup
  REASON → nvidia/nemotron-3-nano-4b     : kill-chain planning, complex reasoning
  VISION → zai-org/glm-4.6v-flash        : image/screenshot evidence analysis

Memory budget:
  granite (~2.5 GB) + nemotron (~3.5 GB) = ~6 GB  → always resident
  glm-vision (~5 GB)                               → on-demand, swaps nemotron out

LM Studio /api/v1/models/load|unload are used for hot-swap.
All three models are served from the same LM Studio instance (port 1234).
"""

from typing import Any, Dict, List, Optional
from enum import Enum

from .lmstudio_client import AIMessage, AIResponse, LMStudioClient


class ModelRole(str, Enum):
    FAST   = "fast"
    REASON = "reason"
    VISION = "vision"


_MODEL_IDS: Dict[ModelRole, str] = {
    ModelRole.FAST:   "ibm/granite-4-micro",
    ModelRole.REASON: "nvidia/nemotron-3-nano-4b",
    ModelRole.VISION: "zai-org/glm-4.6v-flash",
}

# Models that cannot coexist in memory with VISION due to budget constraints.
_SWAPPED_OUT_FOR_VISION: List[ModelRole] = [ModelRole.REASON]


class ModelOrchestrator:
    """Route tasks to the right model role and manage hot-swap on memory pressure.

    All calls go through a single ``LMStudioClient`` instance (one LM Studio
    server).  The orchestrator temporarily loads/unloads models as needed so
    that the combined footprint stays within the M5's unified memory budget.

    Usage:
        orchestrator = ModelOrchestrator(llm_client)
        response = orchestrator.chat(ModelRole.FAST, messages)
        response = orchestrator.chat(ModelRole.REASON, messages)
        response = orchestrator.analyze_image(image_b64, prompt)
    """

    def __init__(self, client: LMStudioClient):
        self._client = client
        self._active: Dict[ModelRole, bool] = {
            ModelRole.FAST:   False,
            ModelRole.REASON: False,
            ModelRole.VISION: False,
        }

    # ------------------------------------------------------------------
    # Internal: model lifecycle
    # ------------------------------------------------------------------

    def _model_id(self, role: ModelRole) -> str:
        return _MODEL_IDS[role]

    def _is_loaded(self, role: ModelRole) -> bool:
        loaded = self._client.list_loaded_models()
        model_id = self._model_id(role)
        return any(model_id in m for m in loaded)

    def _ensure_loaded(self, role: ModelRole) -> None:
        """Load *role* model, hot-swapping conflicting models if needed."""
        if self._is_loaded(role):
            return

        if role == ModelRole.VISION:
            for conflict in _SWAPPED_OUT_FOR_VISION:
                if self._is_loaded(conflict):
                    self._client.unload_model(self._model_id(conflict))
                    self._active[conflict] = False

        self._client.load_model(self._model_id(role))
        self._active[role] = True

    def _restore_after_vision(self) -> None:
        """Reload REASON model after a VISION task if it was swapped out."""
        for role in _SWAPPED_OUT_FOR_VISION:
            if not self._is_loaded(role):
                self._client.load_model(self._model_id(role))
                self._active[role] = True

    # ------------------------------------------------------------------
    # Public: routed chat
    # ------------------------------------------------------------------

    def chat(
        self,
        role: ModelRole,
        messages: List[AIMessage],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> AIResponse:
        """Send a chat request to the model assigned to *role*."""
        self._ensure_loaded(role)

        original_model = self._client.model
        self._client.model = self._model_id(role)
        try:
            return self._client.chat(
                messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        finally:
            self._client.model = original_model
            if role == ModelRole.VISION:
                self._restore_after_vision()

    # ------------------------------------------------------------------
    # Public: task-specific shortcuts
    # ------------------------------------------------------------------

    def generate_hypothesis(self, indicators: Dict[str, Any]) -> AIResponse:
        """FAST model: JSON hypothesis from indicators."""
        return self._client_as(ModelRole.FAST).generate_hypothesis(indicators)

    def plan_from_state(self, system_prompt: str, state_summary: str) -> AIResponse:
        """REASON model: kill-chain planning from environment state."""
        messages = [
            AIMessage(role="system", content=system_prompt),
            AIMessage(role="user",   content=state_summary),
        ]
        return self.chat(ModelRole.REASON, messages, temperature=0.1)

    def analyze_code(self, code: str, context: str = "") -> AIResponse:
        """REASON model: security code analysis."""
        self._ensure_loaded(ModelRole.REASON)
        original_model = self._client.model
        self._client.model = self._model_id(ModelRole.REASON)
        try:
            return self._client.analyze_code(code, context)
        finally:
            self._client.model = original_model

    def analyze_image(self, image_b64: str, prompt: str) -> AIResponse:
        """VISION model: analyze a base64-encoded screenshot or image.

        GLM-4V accepts image content via the OpenAI vision message format.
        """
        self._ensure_loaded(ModelRole.VISION)
        original_model = self._client.model
        self._client.model = self._model_id(ModelRole.VISION)
        try:
            messages = [
                AIMessage(role="system", content="You are a security analyst. Analyze the provided image for threat indicators, anomalies, or evidence relevant to an active investigation."),
                AIMessage(role="user",   content=f"data:image/png;base64,{image_b64}\n\n{prompt}"),
            ]
            return self._client.chat(messages)
        finally:
            self._client.model = original_model
            self._restore_after_vision()

    def validate_vulnerability(self, vuln_data: Dict[str, Any]) -> AIResponse:
        """REASON model: vulnerability validation."""
        self._ensure_loaded(ModelRole.REASON)
        original_model = self._client.model
        self._client.model = self._model_id(ModelRole.REASON)
        try:
            return self._client.validate_vulnerability(vuln_data)
        finally:
            self._client.model = original_model

    def explain_cve(self, cve_id: str, description: str) -> AIResponse:
        """FAST model: concise CVE explanation."""
        self._ensure_loaded(ModelRole.FAST)
        original_model = self._client.model
        self._client.model = self._model_id(ModelRole.FAST)
        try:
            return self._client.explain_cve(cve_id, description)
        finally:
            self._client.model = original_model

    # ------------------------------------------------------------------
    # Internal helper
    # ------------------------------------------------------------------

    def _client_as(self, role: ModelRole) -> LMStudioClient:
        """Temporarily set client model to *role* and return it.

        Caller is responsible for restoring ``self._client.model`` afterward.
        This is a convenience for single-call helpers that use client methods
        directly.
        """
        self._ensure_loaded(role)
        self._client.model = self._model_id(role)
        return self._client

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def status(self) -> Dict[str, Any]:
        """Return which models are currently loaded."""
        loaded = self._client.list_loaded_models()
        return {
            role.value: {
                "model_id": self._model_id(role),
                "loaded": any(self._model_id(role) in m for m in loaded),
            }
            for role in ModelRole
        }
