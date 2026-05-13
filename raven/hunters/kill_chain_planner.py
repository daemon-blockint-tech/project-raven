"""
Kill-chain planning layer (Incalmo architecture, arXiv-2501.16466).
Decouples LLM planning from execution: LLM outputs high-level declarative
tasks aligned to MITRE ATT&CK / cyber kill-chain stages; specialist agents
execute them. Maintains an environment state service to avoid context bloat.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
import json
import time
import uuid


class PendingApprovalError(Exception):
    """Raised when a task requires human approval before execution."""

    def __init__(self, task: "DeclarativeTask"):
        self.task = task
        super().__init__(
            f"Task {task.task_id} ({task.action} on {task.target}) "
            f"requires human approval before execution."
        )


class KillChainStage(Enum):
    """MITRE ATT&CK / Cyber Kill Chain stages"""

    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    C2 = "command_and_control"
    EXFILTRATION = "exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    POST_EXPLOITATION = "post_exploitation"


@dataclass
class DeclarativeTask:
    """High-level declarative task output by the planner LLM"""

    task_id: str
    stage: KillChainStage
    action: str  # e.g. "scan_network", "lateral_move", "exfiltrate"
    target: str  # host, subnet, or asset identifier
    parameters: Dict[str, Any]
    priority: int  # 1 = highest
    depends_on: List[str] = field(default_factory=list)  # task_ids
    status: str = "pending"  # pending | running | done | failed
    result: Optional[Dict[str, Any]] = None
    created_at: float = field(default_factory=time.time)


@dataclass
class EnvironmentState:
    """Structured knowledge base of the scanned environment (avoids context bloat)"""

    hosts: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    services: Dict[str, List[str]] = field(default_factory=dict)
    vulnerabilities: Dict[str, List[str]] = field(default_factory=dict)
    acquired_assets: List[str] = field(default_factory=list)
    attack_paths: List[List[str]] = field(default_factory=list)
    last_updated: float = field(default_factory=time.time)

    def update_host(self, host: str, info: Dict[str, Any]):
        self.hosts[host] = info
        self.last_updated = time.time()

    def update_services(self, host: str, services: List[str]):
        self.services[host] = services
        self.last_updated = time.time()

    def add_vulnerability(self, host: str, vuln: str):
        self.vulnerabilities.setdefault(host, []).append(vuln)
        self.last_updated = time.time()

    def add_acquired_asset(self, asset: str):
        if asset not in self.acquired_assets:
            self.acquired_assets.append(asset)
        self.last_updated = time.time()

    def get_possible_attack_paths(self, target_host: str) -> List[List[str]]:
        """Return known paths that could reach target_host"""
        return [p for p in self.attack_paths if target_host in p]

    def query(self, query_type: str, **kwargs) -> Any:
        """Generic queryable interface for planner/agents (RAG-style)"""
        if query_type == "objective":
            return self.hosts.get("objective", "")
        if query_type == "hosts_on_network":
            subnet = kwargs.get("subnet", "")
            return [h for h in self.hosts if h.startswith(subnet)]
        if query_type == "vulnerable_hosts":
            return list(self.vulnerabilities.keys())
        if query_type == "services_on_host":
            host = kwargs.get("host", "")
            return self.services.get(host, [])
        if query_type == "acquired_assets":
            return self.acquired_assets
        return {}


_STAGES_REQUIRING_APPROVAL: frozenset = frozenset(
    {
        KillChainStage.EXPLOITATION,
        KillChainStage.LATERAL_MOVEMENT,
        KillChainStage.EXFILTRATION,
        KillChainStage.PRIVILEGE_ESCALATION,
        KillChainStage.POST_EXPLOITATION,
    }
)


class KillChainPlanner:
    """
    LLM-assisted planning layer following Incalmo's architecture.
    Generates declarative kill-chain tasks from environment state.
    Delegates execution to specialist agents (nmap, bash, metasploit, etc.).
    """

    def __init__(
        self,
        config: Dict[str, Any],
        tools: Dict[str, Any],
        llm_client: Optional[Any] = None,
    ):
        self.config = config
        self.tools = tools
        self.llm = llm_client
        self.env_state = EnvironmentState()
        self.task_queue: List[DeclarativeTask] = []
        self.completed_tasks: List[DeclarativeTask] = []
        self._pending_approval: Optional[DeclarativeTask] = None

    @property
    def pending_approval(self) -> Optional["DeclarativeTask"]:
        return self._pending_approval

    # ------------------------------------------------------------------
    # LLM-driven planning from environment state
    # ------------------------------------------------------------------

    def plan_from_state(self, objective: str) -> List[DeclarativeTask]:
        """Ask the LLM to generate the next batch of tasks given current env state.

        The LLM receives a compact state summary (no raw tool output) to stay
        within context limits.  Returns an empty list when the LLM is not
        configured or returns no actionable tasks.
        """
        if self.llm is None:
            return []

        from raven.ai.lmstudio_client import AIMessage

        state_summary = {
            "objective": objective,
            "hosts_discovered": list(self.env_state.hosts.keys()),
            "vulnerable_hosts": self.env_state.query("vulnerable_hosts"),
            "acquired_assets": self.env_state.query("acquired_assets"),
            "completed_actions": [t.action for t in self.completed_tasks],
        }

        system = (
            "You are a red-team planning agent following the Incalmo architecture. "
            "Given the current environment state, output a JSON array of the next "
            "tasks to execute. Each task must have: "
            "stage (one of: reconnaissance, exploitation, lateral_movement, "
            "privilege_escalation, exfiltration, command_and_control, installation), "
            "action (str), target (str), parameters (object), priority (int 1=highest). "
            "Output ONLY the JSON array. Stop planning when the objective is met or "
            "no further progress is possible."
        )
        user = json.dumps(state_summary, default=str)

        try:
            response = self.llm.chat(
                [
                    AIMessage(role="system", content=system),
                    AIMessage(role="user", content=user),
                ],
                temperature=0.1,
            )
            raw = response.content.strip()
            items = json.loads(raw)
            if not isinstance(items, list):
                return []
        except Exception:
            return []

        stage_map = {s.value: s for s in KillChainStage}
        tasks = []
        for item in items:
            stage_val = item.get("stage", "reconnaissance")
            stage = stage_map.get(stage_val, KillChainStage.RECONNAISSANCE)
            tasks.append(
                DeclarativeTask(
                    task_id=str(uuid.uuid4()),
                    stage=stage,
                    action=item.get("action", "unknown"),
                    target=item.get("target", ""),
                    parameters=item.get("parameters", {}),
                    priority=int(item.get("priority", 5)),
                )
            )

        self.task_queue.extend(tasks)
        return tasks

    # ------------------------------------------------------------------
    # Static planning fallback (hardcoded initial plan)
    # ------------------------------------------------------------------

    def plan_red_team(
        self, objective: str, target_network: str
    ) -> List[DeclarativeTask]:
        """
        Generate a kill-chain plan for a target network.
        LLM decides WHAT; agents execute HOW.
        """
        tasks = []

        # Stage 1: Reconnaissance
        tasks.append(
            DeclarativeTask(
                task_id=str(uuid.uuid4()),
                stage=KillChainStage.RECONNAISSANCE,
                action="scan_network",
                target=target_network,
                parameters={"scan_type": "service_version", "ports": "top_1000"},
                priority=1,
            )
        )

        # Stage 2: Exploitation planning (depends on recon)
        exploit_task_id = str(uuid.uuid4())
        tasks.append(
            DeclarativeTask(
                task_id=exploit_task_id,
                stage=KillChainStage.EXPLOITATION,
                action="exploit_vulnerabilities",
                target=target_network,
                parameters={"use_metasploit": True},
                priority=2,
                depends_on=[tasks[0].task_id],
            )
        )

        # Stage 3: Lateral movement
        tasks.append(
            DeclarativeTask(
                task_id=str(uuid.uuid4()),
                stage=KillChainStage.LATERAL_MOVEMENT,
                action="lateral_move",
                target="internal_network",
                parameters={"technique": "ssh_key_reuse"},
                priority=3,
                depends_on=[exploit_task_id],
            )
        )

        # Stage 4: Exfiltration
        tasks.append(
            DeclarativeTask(
                task_id=str(uuid.uuid4()),
                stage=KillChainStage.EXFILTRATION,
                action="exfiltrate_data",
                target="critical_assets",
                parameters={"method": "encrypted_channel"},
                priority=4,
                depends_on=[tasks[-1].task_id],
            )
        )

        self.task_queue.extend(tasks)
        return tasks

    def get_next_task(self) -> Optional[DeclarativeTask]:
        """Return the highest-priority ready task (dependencies met)"""
        completed_ids = {t.task_id for t in self.completed_tasks}
        ready = [
            t
            for t in self.task_queue
            if t.status == "pending"
            and all(dep in completed_ids for dep in t.depends_on)
        ]
        if not ready:
            return None
        return sorted(ready, key=lambda t: t.priority)[0]

    def mark_task_done(self, task_id: str, result: Dict[str, Any]):
        """Mark a task complete and update environment state"""
        for task in self.task_queue:
            if task.task_id == task_id:
                task.status = "done"
                task.result = result
                self.completed_tasks.append(task)
                self._update_env_state_from_result(task, result)
                break

    def mark_task_failed(self, task_id: str, error: str):
        for task in self.task_queue:
            if task.task_id == task_id:
                task.status = "failed"
                task.result = {"error": error}
                break

    # ------------------------------------------------------------------
    # Execution dispatch
    # ------------------------------------------------------------------

    def approve_pending_task(self) -> Optional[Dict[str, Any]]:
        """Execute the task that is waiting for human approval.

        Returns the task result, or None if no task is pending.
        """
        task = self._pending_approval
        if task is None:
            return None
        self._pending_approval = None
        return self._dispatch_task(task)

    def reject_pending_task(self) -> Optional[str]:
        """Reject and discard the task awaiting approval."""
        task = self._pending_approval
        if task is None:
            return None
        self._pending_approval = None
        self.mark_task_failed(task.task_id, "rejected by operator")
        return task.task_id

    def execute_task(
        self, task: DeclarativeTask, auto_approve: bool = False
    ) -> Dict[str, Any]:
        """Dispatch task to the appropriate specialist agent.

        Raises PendingApprovalError for destructive stages unless
        auto_approve=True is explicitly passed.
        """
        if task.stage in _STAGES_REQUIRING_APPROVAL and not auto_approve:
            self._pending_approval = task
            raise PendingApprovalError(task)

        return self._dispatch_task(task)

    def _dispatch_task(self, task: DeclarativeTask) -> Dict[str, Any]:
        task.status = "running"

        dispatch = {
            "scan_network":            self._execute_scan,
            "vuln_scan_deep":          self._execute_nuclei,
            "analyze_binary":          self._execute_ghidra,
            "exploit_vulnerabilities": self._execute_exploit,
            "lateral_move":            self._execute_lateral_move,
            "exfiltrate_data":         self._execute_exfiltrate,
            "privilege_escalation":    self._execute_privesc,
            "post_exploitation":       self._execute_empire,
            "malware_analysis":        self._execute_malware_analysis,
        }


        handler = dispatch.get(task.action)
        if not handler:
            result = {"error": f"No agent for action: {task.action}"}
            self.mark_task_failed(task.task_id, result["error"])
            return result

        try:
            result = handler(task)
            self.mark_task_done(task.task_id, result)
            return result
        except Exception as e:
            self.mark_task_failed(task.task_id, str(e))
            return {"error": str(e)}

    def _execute_scan(self, task: DeclarativeTask) -> Dict[str, Any]:
        results = {}
        if "whois" in self.tools:
            results["whois"] = self.tools["whois"].query(task.target)
        if "nmap_scanner" in self.tools:
            results["nmap"] = self.tools["nmap_scanner"].scan_network(task.target, ports="top_100")
        if "projectdiscovery" in self.tools:
            pd = self.tools["projectdiscovery"]
            results["subdomains"] = pd.enumerate_subdomains(task.target)
            results["http_probe"] = pd.probe_http(task.target)
        if "recon_ng" in self.tools:
            results["recon"] = self.tools["recon_ng"].execute_workspace("default", "recon/domains-hosts/brute_hosts", {})
        return {"scan_result": results, "stage": task.stage.value}


    def _execute_exploit(self, task: DeclarativeTask) -> Dict[str, Any]:
        results = []
        vulnerable_hosts = self.env_state.query("vulnerable_hosts")
        for host in vulnerable_hosts:
            vulns = self.env_state.vulnerabilities.get(host, [])
            for vuln in vulns:
                if "exploitdb" in self.tools:
                    results.append({"host": host, "searchsploit": self.tools["exploitdb"].search(vuln)})
                if "metasploit" in self.tools:
                    res = self.tools["metasploit"].exploit(host, vuln)
                    results.append({"host": host, "vuln": vuln, "result": res})
        return {"exploits": results}
    def _execute_lateral_move(self, task: DeclarativeTask) -> Dict[str, Any]:
        if "ssh_manager" not in self.tools:
            return {"error": "ssh tool not available"}
        attack_paths = self.env_state.get_possible_attack_paths(task.target)
        return {"attack_paths_found": len(attack_paths), "paths": attack_paths}

    def _execute_exfiltrate(self, task: DeclarativeTask) -> Dict[str, Any]:
        return {"exfiltrated": self.env_state.acquired_assets}

    def _execute_privesc(self, task: DeclarativeTask) -> Dict[str, Any]:
        return {"status": "privilege_escalation_attempted", "target": task.target}

    def _execute_nuclei(self, task: DeclarativeTask) -> Dict[str, Any]:
        if "nuclei" not in self.tools:
            return {"error": "nuclei tool not available"}
        severity = task.parameters.get("severity", "medium,high,critical")
        tags = task.parameters.get("tags", "")
        result = self.tools["nuclei"].scan(task.target, severity=severity, tags=tags)
        return {
            "success": result.success,
            "findings": result.findings,
            "execution_time": result.execution_time,
        }

    def _execute_ghidra(self, task: DeclarativeTask) -> Dict[str, Any]:
        if "ghidra" not in self.tools:
            return {"error": "ghidra tool not available"}
        result = self.tools["ghidra"].analyze(task.target)
        if not result.success:
            return {"success": False, "error": result.error}
        # Send top decompiled snippet to REASON model for LLM verdict
        llm_verdict = ""
        if result.decompiled and "ai" in self.tools:
            snippets = "\n\n".join(
                f"// {fn}\n{code}" for fn, code in list(result.decompiled.items())[:3]
            )
            try:
                resp = self.tools["ai"].analyze_code(
                    snippets,
                    context=f"Binary: {task.target}, Architecture: {result.architecture}",
                )
                llm_verdict = resp.content
            except Exception:
                pass
        return {
            "success": True,
            "architecture": result.architecture,
            "function_count": result.function_count,
            "suspicious": result.suspicious,
            "strings_sample": result.strings[:20],
            "imports_sample": result.imports[:20],
            "llm_verdict": llm_verdict,
            "execution_time": result.execution_time,
        }

    def _execute_empire(self, task: DeclarativeTask) -> Dict[str, Any]:
        if "empire" not in self.tools:
            return {"error": "empire tool not available"}
        empire = self.tools["empire"]
        agent = task.parameters.get("agent", "")
        if not agent:
            agents = empire.list_agents()
            if not agents:
                return {"error": "no active Empire agents"}
            agent = agents[0].get("name", "")
        module = task.parameters.get("module", "")
        command = task.parameters.get("command", "")
        if module:
            res = empire.execute_module(
                agent, module, task.parameters.get("options", {})
            )
        else:
            res = empire.run_shell(agent, command or "whoami")
        return res.__dict__

    # ------------------------------------------------------------------
    # Environment state updates
    # ------------------------------------------------------------------

    def _update_env_state_from_result(self, task: DeclarativeTask, result: Dict):
        if task.action == "scan_network":
            scan_data = result.get("scan_result", {})
            if isinstance(scan_data, dict):
                for host, info in scan_data.items():
                    self.env_state.update_host(host, info)
                    self.env_state.update_services(host, info.get("services", []))
        elif task.action == "vuln_scan_deep":
            for finding in result.get("findings", []):
                host = finding.get("host") or task.target
                vuln_id = finding.get("template-id", "unknown")
                severity = finding.get("info", {}).get("severity", "info")
                if severity in ("medium", "high", "critical"):
                    self.env_state.add_vulnerability(host, vuln_id)
        elif task.action == "analyze_binary":
            for entry in result.get("suspicious", []):
                func_name = entry.get("name", "unknown")
                self.env_state.add_vulnerability(
                    task.target, f"suspicious_function:{func_name}"
                )
        elif task.action == "exploit_vulnerabilities":
            for exploit in result.get("exploits", []):
                if exploit.get("result", {}).get("success"):
                    self.env_state.add_acquired_asset(exploit["host"])

    # ------------------------------------------------------------------
    # Full autonomous run
    # ------------------------------------------------------------------

    def run(self, objective: str, target_network: str) -> Dict[str, Any]:
        """Execute an autonomous kill-chain exercise.

        Flow:
          1. Seed the queue with the static reconnaissance plan.
          2. Execute ready tasks in priority order.
          3. When the static queue is exhausted, ask the LLM to plan the
             next batch based on current env state.
          4. Repeat until the LLM returns no new tasks or a destructive
             task raises PendingApprovalError (halts and returns status).
        """
        self.task_queue.clear()
        self.completed_tasks.clear()
        self._pending_approval = None
        self.plan_red_team(objective, target_network)
        start = time.time()
        executed = []
        llm_rounds = 0
        max_llm_rounds = self.config.get("max_plan_rounds", 5)

        while True:
            task = self.get_next_task()

            if task is None:
                if self.llm is None or llm_rounds >= max_llm_rounds:
                    break
                new_tasks = self.plan_from_state(objective)
                llm_rounds += 1
                if not new_tasks:
                    break
                continue

            try:
                result = self.execute_task(task)
            except PendingApprovalError as exc:
                return {
                    "objective": objective,
                    "target": target_network,
                    "status": "pending_approval",
                    "pending_task_id": exc.task.task_id,
                    "pending_action": exc.task.action,
                    "pending_stage": exc.task.stage.value,
                    "duration_seconds": round(time.time() - start, 2),
                    "tasks_executed": len(executed),
                    "tasks_completed": len(self.completed_tasks),
                    "acquired_assets": self.env_state.acquired_assets,
                    "stages": executed,
                }

            executed.append(
                {
                    "stage": task.stage.value,
                    "action": task.action,
                    "target": task.target,
                    "status": task.status,
                }
            )

        return {
            "objective": objective,
            "target": target_network,
            "status": "completed",
            "duration_seconds": round(time.time() - start, 2),
            "tasks_executed": len(executed),
            "tasks_completed": len(self.completed_tasks),
            "acquired_assets": self.env_state.acquired_assets,
            "stages": executed,
        }

    def _execute_malware_analysis(self, task: DeclarativeTask) -> Dict[str, Any]:
        """Agentic Malware Analysis Orchestrator integration"""
        target_file = task.target
        results = {}
        if "yara" in self.tools:
            results["yara"] = self.tools["yara"].scan_file(target_file)
        if "radare" in self.tools:
            results["r2_info"] = self.tools["radare"].analyze_binary(target_file)
        if "ghidra" in self.tools:
            results["ghidra"] = self.tools["ghidra"].analyze(target_file)
        if "jadx" in self.tools and target_file.endswith(".apk"):
            results["jadx"] = self.tools["jadx"].decompile_apk(target_file, "/tmp/jadx_out")
        if "volatility" in self.tools and target_file.endswith(".vmem"):
            results["volatility"] = self.tools["volatility"].run_plugin(target_file, "windows.pslist")
        if "cyberchef" in self.tools:
            results["cyberchef"] = self.tools["cyberchef"].bake(target_file, [{"op": "To Base64"}])
        return {"malware_analysis": results}
