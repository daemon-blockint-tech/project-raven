"""Main FastAPI application"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any, Optional
import time

# Import Raven components
from raven.core.threat_detector import ThreatDetector
from raven.core.anomaly_detector import AnomalyDetector
from raven.core.behavioral_profiler import BehavioralProfiler
from raven.tools.ssh_manager import SSHManager
from raven.tools.bash_executor import BashExecutor
from raven.tools.nmap_scanner import NmapScanner
from raven.tools.metasploit_integration import MetasploitIntegration
from raven.tools.nuclei_scanner import NucleiScanner
from raven.tools.empire_client import EmpireClient
from raven.tools.ghidra_analyzer import GhidraAnalyzer
from raven.hunters.hypothesis_generator import HypothesisGenerator
from raven.hunters.automated_investigator import AutomatedInvestigator
from raven.hunters.threat_hunter import ThreatHunter
from raven.hunters.kill_chain_planner import KillChainPlanner, PendingApprovalError
from raven.ml.zero_day_detector import ZeroDayDetector
from raven.ml.behavioral_analyzer import BehavioralAnalyzer
from raven.ml.sequence_analyzer import SequenceAnalyzer
from raven.mitigation.containment_actions import ContainmentActions
from raven.mitigation.remediation_engine import RemediationEngine
from raven.mitigation.response_orchestrator import ResponseOrchestrator
from raven.monitoring.metrics_collector import MetricsCollector
from raven.monitoring.alert_manager import AlertManager, AlertSeverity
from raven.monitoring.dashboard_api import DashboardAPI
from raven.config import settings
from raven.ai import AIMessage, BaseAIClient, ProviderRegistry, SUPPORTED_PROVIDERS
from raven.ai.model_orchestrator import ModelOrchestrator, ModelRole
from raven.integrations.shodan_client import ShodanClient
from raven.auth.dependencies import (
    current_user,
    require_admin,
    require_operator,
    require_viewer,
)
from raven.auth.models import Role, User
from raven.auth.routes import router as auth_router
from raven.audit.middleware import AuditLogMiddleware
from raven.audit.store import audit_store
from raven.observability import (
    MetricsMiddleware,
    configure_logging,
    configure_tracing,
    get_logger,
)
from raven.observability.tracing import instrument_app

# Configure structured logging early (JSON in prod/staging, console in dev)
configure_logging(
    level=settings.log_level,
    json=settings.environment != "dev",
)
log = get_logger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Project Raven API",
    description="Autonomous Defense System with ML/AI for Zero-Day Threat Detection",
    version="0.2.0",
)

# Mount auth router
app.include_router(auth_router)

# Observability middleware (order matters: metrics → audit → CORS)
app.add_middleware(MetricsMiddleware)
app.add_middleware(AuditLogMiddleware, skip_paths=("/health", "/metrics", "/dashboard"))

# CORS — explicit allowlist from settings (no wildcard; refuse '*' in prod via settings)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)

# Tracing (OTel auto-instrument FastAPI + requests when OTEL endpoint set)
if configure_tracing("raven-api"):
    instrument_app(app)

# Global components (in production, use dependency injection)
components = {}


@app.on_event("startup")
async def startup_event():
    """Initialize components on startup"""
    config = {
        "anomaly_threshold": settings.anomaly_threshold,
        "zero_day_confidence": settings.zero_day_confidence,
        "ssh_timeout": settings.ssh_timeout,
        "nmap_timeout": settings.nmap_timeout,
        "metasploit_timeout": settings.metasploit_timeout,
        "enable_metrics": settings.enable_metrics,
        "metrics_port": settings.metrics_port,
        # AI provider (new unified config)
        "ai_provider":     settings.ai_provider,
        "ai_model":        settings.ai_model,
        "ai_api_key":      settings.ai_api_key,
        "ai_base_url":     settings.ai_base_url,
        "ai_timeout":      settings.ai_timeout,
        "ai_temperature":  settings.ai_temperature,
        "ai_max_tokens":   settings.ai_max_tokens,
        # LM Studio backward-compat keys
        "lmstudio_base_url": settings.lmstudio_base_url,
        "lmstudio_model": settings.lmstudio_model,
        "lmstudio_api_key": settings.lmstudio_api_key,
        "lmstudio_timeout": settings.lmstudio_timeout,
        "lmstudio_temperature": settings.lmstudio_temperature,
        "lmstudio_max_tokens": settings.lmstudio_max_tokens,
        # OpenRouter extras
        "openrouter_http_referer": settings.openrouter_http_referer,
        "openrouter_title": settings.openrouter_title,
        # System prompt (path resolved at startup; empty = disabled)
        "ai_system_prompt_path": settings.ai_system_prompt_path,
    }

    # Initialise provider registry (hot-swappable AI client)
    registry = ProviderRegistry.get_instance()
    registry.initialise_from_config(config)
    components["ai"] = registry.get_client()
    components["model_orchestrator"] = ModelOrchestrator(components["ai"])

    # Initialize Shodan client (optional — skipped if no API key configured)
    if settings.shodan_api_key:
        try:
            components["shodan"] = ShodanClient({
                "shodan_api_key": settings.shodan_api_key,
                "shodan_max_results": settings.shodan_max_results,
            })
        except Exception:
            components["shodan"] = None
    else:
        components["shodan"] = None
    
    # Initialize core components
    components["threat_detector"] = ThreatDetector(config)
    components["anomaly_detector"] = AnomalyDetector(config)
    components["behavioral_profiler"] = BehavioralProfiler(config)
    
    # Initialize tools
    components["ssh_manager"] = SSHManager(config)
    components["bash_executor"] = BashExecutor(config)
    components["nmap_scanner"] = NmapScanner(config)
    components["metasploit"] = MetasploitIntegration(config)
    components["nuclei"] = NucleiScanner(config)
    components["empire"] = EmpireClient(config)
    components["ghidra"] = GhidraAnalyzer(config)
    
    ai_client = components["ai"]

    # Initialize hunters
    components["hypothesis_generator"] = HypothesisGenerator(config, llm_client=ai_client)
    components["investigator"] = AutomatedInvestigator(config, components, llm_client=ai_client)
    components["kill_chain_planner"] = KillChainPlanner(config, components, llm_client=ai_client)
    components["threat_hunter"] = ThreatHunter(
        config,
        components["hypothesis_generator"],
        components["investigator"],
        components
    )
    
    # Initialize ML components
    components["zero_day_detector"] = ZeroDayDetector(config)
    components["behavioral_analyzer"] = BehavioralAnalyzer(config)
    components["sequence_analyzer"] = SequenceAnalyzer(config)
    
    # Initialize mitigation
    components["containment"] = ContainmentActions(config, components)
    components["remediation"] = RemediationEngine(config, components)
    components["response_orchestrator"] = ResponseOrchestrator(
        config,
        components["containment"],
        components["remediation"]
    )
    
    # Initialize monitoring
    components["metrics"] = MetricsCollector(config)
    components["alerts"] = AlertManager(config)
    
    # Register alert handlers
    components["alerts"].register_handler(
        AlertSeverity.CRITICAL,
        lambda alert: print(f"CRITICAL ALERT: {alert.title}")
    )
    
    # Initialize dashboard API
    components["dashboard"] = DashboardAPI(
        config,
        components["metrics"],
        components["alerts"]
    )
    
    # Mount dashboard app
    app.mount("/dashboard", components["dashboard"].get_app())


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    # Close SSH connections
    if "ssh_manager" in components:
        components["ssh_manager"].disconnect_all()
    
    # Disconnect Metasploit
    if "metasploit" in components:
        components["metasploit"].disconnect()


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Project Raven API",
        "version": "0.1.0",
        "status": "operational"
    }


@app.get("/health/ready")
async def health_ready():
    """Readiness probe — true once dependencies are reachable.

    Used by K8s readinessProbe to route traffic only when the pod can
    actually serve requests (DB, Redis, AI provider).
    """
    checks = {}

    # AI provider
    ai = components.get("ai")
    if ai is not None:
        try:
            checks["ai"] = bool(ai.is_available())
        except Exception:
            checks["ai"] = False
    else:
        checks["ai"] = False

    ready = all(checks.values())
    status_code = 200 if ready else 503
    from fastapi.responses import JSONResponse
    return JSONResponse(
        status_code=status_code,
        content={"ready": ready, "checks": checks},
    )


@app.get("/health/startup")
async def health_startup():
    """Startup probe — true once startup_event completed.

    Allows long ML model warm-up without killing the pod. K8s uses this
    via startupProbe with a 60s window.
    """
    started = bool(components.get("threat_detector") is not None)
    from fastapi.responses import JSONResponse
    return JSONResponse(
        status_code=200 if started else 503,
        content={"started": started},
    )


@app.get("/health")
async def health():
    """Liveness probe — process is alive."""
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "components": {
            "threat_detector": "operational",
            "anomaly_detector": "operational",
            "threat_hunter": "operational",
            "mitigation": "operational",
            "monitoring": "operational"
        }
    }


def _jail_scan_path(raw: str) -> str:
    """Verify a user-supplied repo path stays under settings.scan_root.

    Closes F2 (filesystem disclosure via /hunt/code and /hunt/variant).
    Raises 403 if traversal is attempted; 400 if scan_root not configured.
    """
    from pathlib import Path as _Path
    if not settings.scan_root:
        raise HTTPException(status_code=400, detail="scan_root is not configured")
    root = _Path(settings.scan_root).resolve()
    target = _Path(raw).resolve(strict=False)
    try:
        target.relative_to(root)
    except ValueError:
        raise HTTPException(
            status_code=403,
            detail=f"repo_path must stay under scan_root ({root})",
        )
    return str(target)


@app.post("/analyze")
async def analyze_event(
    event_data: Dict[str, Any],
    user: User = Depends(require_operator),
):
    """Analyze an event for threats"""
    start_time = time.time()
    
    # Run threat detection
    threats = components["threat_detector"].analyze(event_data)
    
    # Record metrics
    detection_time = time.time() - start_time
    components["metrics"].record_detection_time(detection_time)
    
    for threat in threats:
        components["metrics"].record_threat_detected(
            threat.severity.value,
            threat.threat_type.value
        )
        
        # Create alert for high/critical threats
        if threat.severity.value in ["high", "critical"]:
            components["alerts"].create_alert(
                title=f"Threat Detected: {threat.threat_type.value}",
                description=threat.description,
                severity=AlertSeverity[threat.severity.value.upper()],
                source="threat_detector",
                metadata={"threat_id": threat.threat_id}
            )
    
    return {
        "threats": [
            {
                "id": t.threat_id,
                "type": t.threat_type.value,
                "severity": t.severity.value,
                "confidence": t.confidence,
                "description": t.description
            }
            for t in threats
        ],
        "detection_time": detection_time
    }


@app.post("/hunt")
async def start_threat_hunt(
    indicators: Dict[str, Any],
    user: User = Depends(require_operator),
):
    """Start a threat hunting session"""
    session = components["threat_hunter"].start_hunt(indicators)
    
    # Update metrics
    components["metrics"].update_active_hypotheses(
        len(components["hypothesis_generator"].list_hypotheses(status="pending"))
    )
    
    # Create alert if threats found
    if session.threats_found > 0:
        components["alerts"].create_alert(
            title=f"Threat Hunt Completed: {session.threats_found} Threats Found",
            description=f"Hunting session {session.session_id} found {session.threats_found} confirmed threats",
            severity=AlertSeverity.HIGH,
            source="threat_hunter",
            metadata={"session_id": session.session_id}
        )
    
    return {
        "session_id": session.session_id,
        "hypotheses_generated": session.hypotheses_generated,
        "investigations_completed": session.investigations_completed,
        "threats_found": session.threats_found,
        "duration": session.end_time - session.start_time if session.end_time else 0
    }


@app.post("/hunt/variant")
async def variant_hunt(
    payload: Dict[str, Any],
    user: User = Depends(require_operator),
):
    """
    Variant analysis: find incomplete patches, deep-precondition paths,
    algorithm assumption violations, and dangerous patterns.
    Body: {"repo_path": "/path/to/repo"} (must be under settings.scan_root)
    """
    from raven.ml.variant_analyzer import VariantAnalyzer
    repo_path = payload.get("repo_path")
    if not repo_path:
        raise HTTPException(status_code=400, detail="repo_path is required")
    repo_path = _jail_scan_path(repo_path)

    analyzer = VariantAnalyzer({"variant_confidence_threshold": 0.5})
    findings = analyzer.analyze_repository(repo_path)
    summary = analyzer.summarize(findings, base_path=repo_path)

    if summary["high_confidence"] > 0:
        components["alerts"].create_alert(
            title=f"Variant Analysis: {summary['high_confidence']} High-Confidence Findings",
            description=f"Variant scan of {repo_path} found {summary['total_findings']} total issues",
            severity=AlertSeverity.HIGH,
            source="variant_analyzer",
            metadata={"by_type": summary["by_type"]},
        )

    return summary


@app.post("/hunt/code")
async def code_hunt(
    payload: Dict[str, Any],
    user: User = Depends(require_operator),
):
    """
    Defensively scan a repository for exploitable taint flows.
    Body: {"repo_path": "/path/to/repo"} (must be under settings.scan_root)
    """
    repo_path = payload.get("repo_path")
    if not repo_path:
        raise HTTPException(status_code=400, detail="repo_path is required")
    repo_path = _jail_scan_path(repo_path)

    result = components["threat_hunter"].code_hunt(repo_path)

    if result["high_confidence_flows"] > 0:
        components["alerts"].create_alert(
            title=f"Code Hunt: {result['high_confidence_flows']} High-Confidence Flows Found",
            description=f"Taint-flow scan of {repo_path} found exploitable paths",
            severity=AlertSeverity.HIGH,
            source="code_flow_scanner",
            metadata={"report_id": result["report_id"]}
        )

    return result


@app.post("/mitigate")
async def execute_mitigation(
    threat_id: str,
    threat_type: str,
    user: User = Depends(require_operator),
):
    """Execute automated mitigation for a threat"""
    # Create response plan
    plan = components["response_orchestrator"].create_response_plan(
        {"threat_id": threat_id},
        threat_type
    )
    
    # Execute plan
    execution = components["response_orchestrator"].execute_plan(plan)
    
    # Record metrics
    if execution.success:
        components["metrics"].record_threat_blocked("automated")
    
    return {
        "plan_id": plan.plan_id,
        "execution_id": execution.execution_id,
        "success": execution.success,
        "execution_time": execution.execution_time,
        "actions_executed": len(execution.results)
    }


@app.get("/metrics")
async def get_metrics():
    """Prometheus metrics exposition (text/plain; openmetrics-compatible)."""
    from fastapi.responses import Response as _Response
    from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
    return _Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/metrics/summary")
async def get_metrics_summary():
    """Human-readable metrics summary (legacy endpoint, still used by dashboard)."""
    return components["metrics"].get_summary()


@app.get("/alerts")
async def get_alerts():
    """Get security alerts"""
    return components["alerts"].get_alert_summary()


# ------------------------------------------------------------------
# Kill-chain planner endpoints
# ------------------------------------------------------------------

@app.post("/hunt/killchain")
async def run_kill_chain(
    payload: Dict[str, Any],
    user: User = Depends(require_operator),
):
    """
    Run an autonomous kill-chain exercise.
    Body: {"objective": str, "target_network": str}
    Returns immediately with status=pending_approval when a destructive
    stage is reached, requiring a follow-up call to /hunt/killchain/approve.
    """
    objective = payload.get("objective", "")
    target = payload.get("target_network", "")
    if not objective or not target:
        raise HTTPException(status_code=400, detail="objective and target_network are required")
    planner: KillChainPlanner = components["kill_chain_planner"]
    result = planner.run(objective, target)
    return result


@app.post("/hunt/killchain/approve")
async def approve_kill_chain_task(user: User = Depends(require_admin)):
    """Approve the task that is pending human review and execute it."""
    planner: KillChainPlanner = components["kill_chain_planner"]
    if planner.pending_approval is None:
        raise HTTPException(status_code=404, detail="No task pending approval")
    result = planner.approve_pending_task()
    return {"approved": True, "result": result}


@app.post("/hunt/killchain/reject")
async def reject_kill_chain_task(user: User = Depends(require_admin)):
    """Reject and discard the task that is pending human review."""
    planner: KillChainPlanner = components["kill_chain_planner"]
    if planner.pending_approval is None:
        raise HTTPException(status_code=404, detail="No task pending approval")
    task_id = planner.reject_pending_task()
    return {"rejected": True, "task_id": task_id}


@app.post("/investigate/target")
async def set_investigation_target(
    payload: Dict[str, Any],
    user: User = Depends(require_operator),
):
    """
    Set the SSH host used for automated investigations.
    Body: {"host": "192.168.1.10"}
    The host must already have an active connection via SSHManager.
    """
    host = payload.get("host", "")
    if not host:
        raise HTTPException(status_code=400, detail="host is required")
    investigator: AutomatedInvestigator = components["investigator"]
    investigator.set_target_host(host)
    return {"investigation_target": host}


# ------------------------------------------------------------------
# AI provider endpoints (runtime switch — no restart needed)
# ------------------------------------------------------------------

@app.get("/ai/provider")
async def ai_provider_status():
    """Return the active provider, model, and connection status."""
    return ProviderRegistry.get_instance().status()


@app.post("/ai/provider")
async def ai_provider_switch(
    payload: Dict[str, Any],
    user: User = Depends(require_admin),
):
    """
    Hot-swap the AI provider at runtime. **Admin role required.**

    Body (all optional except provider):
        {"provider": "openrouter", "api_key": "sk-or-...",
         "model": "nous-hermes-2-mixtral-8x7b", "base_url": ""}

    Supports 'provider:model' shorthand in the model field.

    Security: `base_url` is validated against an allowlist composed of the
    built-in provider defaults plus `settings.ai_allowed_base_urls`.
    This closes F1 (credential exfil via base_url override).
    """
    provider = payload.get("provider", "").strip()
    if not provider:
        raise HTTPException(status_code=400, detail="provider is required")

    base_url = (payload.get("base_url", "") or "").strip()
    if base_url:
        allowed = set(settings.ai_allowed_base_urls)
        for info in SUPPORTED_PROVIDERS.values():
            if info.default_base_url:
                allowed.add(info.default_base_url.rstrip("/"))
        if base_url.rstrip("/") not in allowed:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"base_url not in allowlist. Configure AI_ALLOWED_BASE_URLS "
                    f"or use a built-in provider default."
                ),
            )

    try:
        registry = ProviderRegistry.get_instance()
        client = registry.switch(
            provider=provider,
            model=payload.get("model", ""),
            api_key=payload.get("api_key", ""),
            base_url=base_url,
        )
        components["ai"] = client
        if "model_orchestrator" in components:
            components["model_orchestrator"]._client = client
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return registry.status()


@app.post("/ai/model")
async def ai_model_switch(
    payload: Dict[str, Any],
    user: User = Depends(require_admin),
):
    """
    Change only the model (keeps current provider and API key).

    Body: {"model": "claude-3-5-sonnet-20241022"}
    Supports 'provider:model' shorthand — switches provider too if prefix given.
    """
    model = payload.get("model", "").strip()
    if not model:
        raise HTTPException(status_code=400, detail="model is required")
    registry = ProviderRegistry.get_instance()
    if ":" in model:
        from raven.ai.base import parse_provider_model
        inferred_provider, bare_model = parse_provider_model(model)
        if inferred_provider:
            client = registry.switch(provider=inferred_provider, model=bare_model)
        else:
            client = registry.set_model(bare_model)
    else:
        client = registry.set_model(model)
    components["ai"] = client
    if "model_orchestrator" in components:
        components["model_orchestrator"]._client = client
    return registry.status()


@app.get("/ai/provider/profiles")
async def ai_list_profiles():
    """List all saved provider profiles."""
    return {"profiles": ProviderRegistry.get_instance().list_profiles()}


# Profile name validator (closes F5: path traversal in profile names)
_PROFILE_NAME_RE = __import__("re").compile(r"^[A-Za-z0-9_-]{1,64}$")


def _validate_profile_name(name: str) -> str:
    if not _PROFILE_NAME_RE.match(name):
        raise HTTPException(
            status_code=400,
            detail="Profile name must match ^[A-Za-z0-9_-]{1,64}$",
        )
    return name


@app.post("/ai/provider/profiles/{name}")
async def ai_save_profile(
    name: str,
    user: User = Depends(require_admin),
):
    """Save the current provider configuration as a named profile. Admin-only."""
    name = _validate_profile_name(name)
    path = ProviderRegistry.get_instance().save_profile(name)
    return {"saved": name, "path": str(path)}


@app.put("/ai/provider/profiles/{name}")
async def ai_load_profile(
    name: str,
    user: User = Depends(require_admin),
):
    """Load a saved profile and hot-swap the active client. Admin-only."""
    name = _validate_profile_name(name)
    try:
        client = ProviderRegistry.get_instance().load_profile(name)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    components["ai"] = client
    if "model_orchestrator" in components:
        components["model_orchestrator"]._client = client
    return ProviderRegistry.get_instance().status()


@app.delete("/ai/provider/profiles/{name}")
async def ai_delete_profile(
    name: str,
    user: User = Depends(require_admin),
):
    """Delete a saved profile. Admin-only."""
    name = _validate_profile_name(name)
    deleted = ProviderRegistry.get_instance().delete_profile(name)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Profile not found: {name!r}")
    return {"deleted": name}


@app.get("/ai/system-prompt")
async def ai_get_system_prompt():
    """Return the currently active system prompt."""
    registry = ProviderRegistry.get_instance()
    prompt = registry.get_system_prompt()
    return {
        "system_prompt": prompt,
        "length": len(prompt),
        "active": bool(prompt),
    }


@app.post("/ai/system-prompt")
async def ai_set_system_prompt(
    payload: Dict[str, Any],
    user: User = Depends(require_admin),
):
    """
    Set a new system prompt at runtime (affects all subsequent AI calls).

    Body options (mutually exclusive, checked in order):
      {"prompt": "You are Raven..."}           — raw text
      {"file": "RAVEN_SYSTEM_PROMPT.md"}       — load from file (must be inside CWD)
    """
    import os
    from pathlib import Path as _Path

    registry = ProviderRegistry.get_instance()
    if "file" in payload:
        raw_path = str(payload["file"])
        # Jail: resolved path MUST live inside the server CWD to prevent
        # arbitrary file read (e.g. /etc/passwd) via this unauthenticated endpoint.
        try:
            target = _Path(raw_path).resolve(strict=False)
            cwd = _Path(os.getcwd()).resolve()
            target.relative_to(cwd)
        except ValueError:
            raise HTTPException(
                status_code=403,
                detail=f"Path outside server working directory is not allowed: {raw_path!r}",
            )
        try:
            prompt = registry.load_system_prompt_from_file(str(target))
        except FileNotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e))
    elif "prompt" in payload:
        prompt = payload["prompt"]
        registry.set_system_prompt(prompt)
    else:
        raise HTTPException(status_code=400, detail="Provide 'prompt' (text) or 'file' (path)")
    return {"set": True, "length": len(prompt)}


@app.delete("/ai/system-prompt")
async def ai_clear_system_prompt(user: User = Depends(require_admin)):
    """Clear the system prompt (AI calls will have no injected context). Admin-only."""
    ProviderRegistry.get_instance().set_system_prompt("")
    return {"cleared": True}


@app.get("/ai/providers")
async def ai_list_providers():
    """List all supported providers with example models."""
    return {
        "providers": [
            {
                "name": p.name,
                "description": p.description,
                "needs_api_key": p.needs_api_key,
                "default_base_url": p.default_base_url,
                "example_models": p.example_models,
            }
            for p in SUPPORTED_PROVIDERS.values()
        ]
    }


@app.get("/ai/models/status")
async def ai_models_status():
    """Show which specialist models (fast/reason/vision) are currently loaded."""
    orchestrator: ModelOrchestrator = components.get("model_orchestrator")
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Model orchestrator not initialized")
    return orchestrator.status()


@app.get("/ai/status")
async def ai_status():
    """Check whether the active AI provider is reachable and list loaded models."""
    ai: BaseAIClient = components.get("ai")
    if not ai:
        raise HTTPException(status_code=503, detail="AI client not initialized")
    available = ai.is_available()
    models = ai.list_loaded_models() if available else []
    return {
        "available": available,
        "provider": ai.provider_name,
        "base_url": ai.base_url,
        "configured_model": ai.model or "(auto)",
        "loaded_models": models,
    }


@app.post("/ai/analyze")
async def ai_analyze_code(
    payload: Dict[str, Any],
    user: User = Depends(require_operator),
):
    """
    Send code to the local LLM for security analysis.
    Body: {"code": "...", "context": "optional hint"}
    """
    ai: BaseAIClient = components.get("ai")
    if not ai:
        raise HTTPException(status_code=503, detail="AI client not initialized")
    code = payload.get("code", "")
    if not code:
        raise HTTPException(status_code=400, detail="code is required")
    try:
        response = ai.analyze_code(code, context=payload.get("context", ""))
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    return {
        "analysis": response.content,
        "reasoning": response.reasoning,
        "model": response.model,
        "tokens": {
            "prompt": response.prompt_tokens,
            "completion": response.completion_tokens,
        },
    }


@app.post("/ai/hypothesis")
async def ai_generate_hypothesis(
    payload: Dict[str, Any],
    user: User = Depends(require_operator),
):
    """
    Generate a threat hunting hypothesis from indicators using the local LLM.
    Body: {"indicators": {...}}
    """
    ai: BaseAIClient = components.get("ai")
    if not ai:
        raise HTTPException(status_code=503, detail="AI client not initialized")
    indicators = payload.get("indicators")
    if not indicators:
        raise HTTPException(status_code=400, detail="indicators is required")
    try:
        response = ai.generate_hypothesis(indicators)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    return {
        "hypothesis": response.content,
        "model": response.model,
    }


@app.post("/ai/models/load")
async def ai_load_model(
    payload: Dict[str, Any],
    user: User = Depends(require_admin),
):
    """
    Load a model in LM Studio via POST /api/v1/models/load.
    Body: {"model": "ibm/granite-4-micro", "context_length": 8192}
    """
    ai: BaseAIClient = components.get("ai")
    if not ai:
        raise HTTPException(status_code=503, detail="AI client not initialized")
    model = payload.get("model")
    if not model:
        raise HTTPException(status_code=400, detail="model is required")
    try:
        result = ai.load_model(model, context_length=payload.get("context_length"))
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    return result


@app.post("/ai/models/unload")
async def ai_unload_model(
    payload: Dict[str, Any],
    user: User = Depends(require_admin),
):
    """
    Unload a model in LM Studio via POST /api/v1/models/unload.
    Body: {"model": "ibm/granite-4-micro"}
    """
    ai: BaseAIClient = components.get("ai")
    if not ai:
        raise HTTPException(status_code=503, detail="AI client not initialized")
    model = payload.get("model")
    if not model:
        raise HTTPException(status_code=400, detail="model is required")
    try:
        result = ai.unload_model(model)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    return result


@app.post("/ai/validate")
async def ai_validate_vulnerability(
    payload: Dict[str, Any],
    user: User = Depends(require_operator),
):
    """
    Ask the local LLM to validate a potential vulnerability finding.
    Body: {"vuln_data": {...}}
    """
    ai: BaseAIClient = components.get("ai")
    if not ai:
        raise HTTPException(status_code=503, detail="AI client not initialized")
    vuln_data = payload.get("vuln_data")
    if not vuln_data:
        raise HTTPException(status_code=400, detail="vuln_data is required")
    try:
        response = ai.validate_vulnerability(vuln_data)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    return {
        "validation": response.content,
        "model": response.model,
    }


# ------------------------------------------------------------------
# Shodan endpoints
# ------------------------------------------------------------------

def _require_shodan() -> ShodanClient:
    shodan = components.get("shodan")
    if not shodan:
        raise HTTPException(
            status_code=503,
            detail="Shodan is not configured. Set SHODAN_API_KEY in your .env file."
        )
    return shodan


@app.get("/shodan/status")
async def shodan_status():
    """Return Shodan API key plan info and credit balance."""
    shodan = _require_shodan()
    try:
        info = shodan.api_info()
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    return info


@app.get("/shodan/host/{ip}")
async def shodan_host(ip: str, history: bool = False):
    """
    Get all Shodan data for an IP: open ports, banners, CVEs, honeyscore.
    """
    shodan = _require_shodan()
    try:
        host = shodan.host_info(ip, history=history)
    except (RuntimeError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    return shodan.serialize_host(host)


@app.post("/shodan/search")
async def shodan_search(
    payload: Dict[str, Any],
    user: User = Depends(require_operator),
):
    """
    Generic Shodan search.
    Body: {"query": "apache port:80", "max_results": 20, "facets": ["country", "org"]}
    """
    shodan = _require_shodan()
    query = payload.get("query")
    if not query:
        raise HTTPException(status_code=400, detail="query is required")
    try:
        result = shodan.search(
            query,
            max_results=payload.get("max_results"),
            facets=payload.get("facets"),
        )
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    return shodan.serialize_result(result)


@app.get("/shodan/cve/{cve_id}")
async def shodan_cve_exposure(cve_id: str):
    """
    Find internet-exposed hosts vulnerable to a CVE.
    Returns total count + sample of 10 hosts.
    """
    shodan = _require_shodan()
    try:
        result = shodan.find_exposed_hosts_for_cve(cve_id)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    return result


@app.post("/shodan/enrich")
async def shodan_enrich_ip(
    payload: Dict[str, Any],
    user: User = Depends(require_operator),
):
    """
    Enrich a threat indicator IP with Shodan context (ports, vulns, honeyscore).
    Body: {"ip": "1.2.3.4"}
    """
    shodan = _require_shodan()
    ip = payload.get("ip")
    if not ip:
        raise HTTPException(status_code=400, detail="ip is required")
    try:
        enrichment = shodan.enrich_threat_indicator(ip)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return enrichment


@app.get("/shodan/domain/{domain}")
async def shodan_domain(domain: str):
    """Get DNS records and subdomains for a domain via Shodan."""
    shodan = _require_shodan()
    try:
        result = shodan.domain_info(domain)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    return result


@app.post("/shodan/exploits")
async def shodan_exploits(
    payload: Dict[str, Any],
    user: User = Depends(require_operator),
):
    """
    Search Shodan Exploits database.
    Body: {"query": "CVE-2021-44228 log4j"}
    """
    shodan = _require_shodan()
    query = payload.get("query")
    if not query:
        raise HTTPException(status_code=400, detail="query is required")
    try:
        exploits = shodan.search_exploits(query)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    return {"total": len(exploits), "exploits": exploits}


@app.get("/shodan/search/facets")
async def shodan_search_facets():
    """List all available Shodan search facets (free, no credits consumed)."""
    shodan = _require_shodan()
    try:
        return shodan.search_facets()
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))


@app.get("/shodan/search/filters")
async def shodan_search_filters():
    """List all search filters usable in Shodan queries."""
    shodan = _require_shodan()
    try:
        return shodan.search_filters()
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))


@app.get("/shodan/search/tokens")
async def shodan_search_tokens(query: str):
    """
    Break a Shodan query into tokens to see which filters are active.
    Useful for validating a query before running a credit-consuming search.
    """
    shodan = _require_shodan()
    try:
        return shodan.search_tokens(query)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))


@app.post("/shodan/scan")
async def shodan_request_scan(
    payload: Dict[str, Any],
    user: User = Depends(require_admin),
):
    """
    Request Shodan to crawl a list of IPs / CIDR netblocks (1 IP = 1 scan credit, paid plan required).
    Body: {"ips": ["1.2.3.4", "10.0.0.0/24"]}
    """
    shodan = _require_shodan()
    ips = payload.get("ips", [])
    if not ips:
        raise HTTPException(status_code=400, detail="ips list is required")
    try:
        scan = shodan.request_scan(ips)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    return {"scan_id": scan.scan_id, "status": scan.status,
            "count": scan.count, "credits_left": scan.credits_left}


@app.get("/shodan/scan/{scan_id}")
async def shodan_scan_status(scan_id: str):
    """Check the status of a submitted Shodan scan (SUBMITTING/QUEUE/PROCESSING/DONE)."""
    shodan = _require_shodan()
    try:
        scan = shodan.scan_status(scan_id)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    return {"scan_id": scan.scan_id, "status": scan.status,
            "count": scan.count, "created": scan.created}


@app.get("/shodan/scans")
async def shodan_list_scans():
    """List all on-demand scans on the account."""
    shodan = _require_shodan()
    try:
        scans = shodan.list_scans()
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    return [{"scan_id": s.scan_id, "status": s.status,
             "count": s.count, "created": s.created} for s in scans]


@app.post("/shodan/alerts")
async def shodan_create_alert(
    payload: Dict[str, Any],
    user: User = Depends(require_admin),
):
    """
    Create a network alert to monitor IPs/CIDRs for new Shodan discoveries.
    Body: {"name": "My Infra", "ips": ["1.2.3.4", "10.0.0.0/24"], "expires": 0}
    """
    shodan = _require_shodan()
    name = payload.get("name")
    ips = payload.get("ips", [])
    if not name or not ips:
        raise HTTPException(status_code=400, detail="name and ips are required")
    try:
        alert = shodan.create_alert(name, ips, expires=payload.get("expires", 0))
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    return {"alert_id": alert.alert_id, "name": alert.name,
            "size": alert.size, "created": alert.created}


@app.get("/shodan/alerts")
async def shodan_list_alerts():
    """List all active network alerts on the account."""
    shodan = _require_shodan()
    try:
        alerts = shodan.list_alerts()
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    return [{"alert_id": a.alert_id, "name": a.name, "filters": a.filters,
             "size": a.size, "has_triggers": a.has_triggers} for a in alerts]


@app.delete("/shodan/alerts/{alert_id}")
async def shodan_delete_alert(
    alert_id: str,
    user: User = Depends(require_admin),
):
    """Delete a network alert."""
    shodan = _require_shodan()
    try:
        success = shodan.delete_alert(alert_id)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    return {"success": success}


@app.get("/shodan/alerts/triggers")
async def shodan_alert_triggers():
    """List all available alert trigger types (malware, ics, open_database, etc.)."""
    shodan = _require_shodan()
    try:
        return shodan.list_alert_triggers()
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))


@app.put("/shodan/alerts/{alert_id}/trigger/{trigger}")
async def shodan_enable_trigger(
    alert_id: str,
    trigger: str,
    user: User = Depends(require_admin),
):
    """
    Enable a trigger on a network alert.
    trigger: comma-separated names e.g. malware,open_database
    """
    shodan = _require_shodan()
    try:
        success = shodan.enable_alert_trigger(alert_id, trigger)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    return {"success": success}


# ------------------------------------------------------------------
# Audit log retrieval
# ------------------------------------------------------------------

@app.get("/audit/log")
async def get_audit_log(
    limit: int = 100,
    actor: Optional[str] = None,
    user: User = Depends(require_admin),
):
    """Return the most recent audit entries. Admin-only.

    Query params:
        limit: maximum entries to return (1..1000, default 100)
        actor: optional filter by username
    """
    limit = max(1, min(int(limit), 1000))
    return {
        "total": audit_store().count(),
        "entries": audit_store().tail(n=limit, actor=actor),
    }
