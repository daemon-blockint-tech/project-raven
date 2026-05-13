"""Automated investigation of threat hypotheses"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import json
import time
import uuid


@dataclass
class InvestigationResult:
    """Result of an investigation"""

    investigation_id: str
    hypothesis_id: str
    findings: List[Dict[str, Any]]
    evidence: List[Dict[str, Any]]
    confidence: float
    conclusion: str
    execution_time: float
    timestamp: float


_SSH_COMMANDS: Dict[str, List[str]] = {
    "connection": [
        "ss -tnp 2>/dev/null || netstat -tnp 2>/dev/null",
        "last -n 50 2>/dev/null",
        r"grep 'Accepted\|Failed' /var/log/auth.log 2>/dev/null | tail -100",
    ],
    "process": [
        "ps auxf 2>/dev/null",
        "ls -la /proc/*/exe 2>/dev/null | grep -v 'Permission denied' | head -60",
    ],
    "file": [
        "find /tmp /var/tmp /dev/shm -type f -newer /etc/passwd 2>/dev/null",
        "find /home -name '.*' -type f -newer /etc/passwd 2>/dev/null | head -40",
    ],
    "network": [
        "ss -unp 2>/dev/null || netstat -unp 2>/dev/null",
        "cat /etc/resolv.conf 2>/dev/null",
        "journalctl -u systemd-resolved --no-pager -n 100 2>/dev/null || true",
    ],
    "persistence": [
        "crontab -l 2>/dev/null; ls /etc/cron* 2>/dev/null",
        "systemctl list-units --type=service --state=running --no-pager 2>/dev/null",
        "ls -la /etc/systemd/system/ 2>/dev/null | grep -v '^total'",
        "cat /etc/rc.local 2>/dev/null || true",
    ],
}


class AutomatedInvestigator:
    """Investigate threat hypotheses by executing forensic commands over SSH.

    When an SSH manager is present in ``tools``, each investigation step
    runs real commands on the target host.  When an LLM client is present,
    it draws the final conclusion from actual command output rather than
    a confidence threshold heuristic.
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
        self._ssh_host: Optional[str] = config.get("investigation_host")

    def set_target_host(self, host: str) -> None:
        """Set (or change) the SSH host used for investigations."""
        self._ssh_host = host

    def investigate(self, hypothesis_id: str, hypothesis: Any) -> InvestigationResult:
        start_time = time.time()
        findings: List[Dict[str, Any]] = []
        evidence: List[Dict[str, Any]] = []

        for step in hypothesis.investigation_steps:
            result = self._execute_investigation_step(step, hypothesis)
            findings.append(result)
            if result.get("evidence"):
                evidence.extend(result["evidence"])

        confidence = self._calculate_confidence(findings)
        conclusion = self._draw_conclusion(
            findings, evidence, confidence, hypothesis.attack_vector
        )

        return InvestigationResult(
            investigation_id=str(uuid.uuid4()),
            hypothesis_id=hypothesis_id,
            findings=findings,
            evidence=evidence,
            confidence=confidence,
            conclusion=conclusion,
            execution_time=round(time.time() - start_time, 3),
            timestamp=time.time(),
        )

    # ------------------------------------------------------------------
    # Step routing
    # ------------------------------------------------------------------

    def _execute_investigation_step(self, step: str, hypothesis: Any) -> Dict[str, Any]:
        step_lower = step.lower()
        if (
            "ssh" in step_lower
            or "connection" in step_lower
            or "authenticat" in step_lower
        ):
            return self._run_ssh_commands("connection", step)
        if "process" in step_lower:
            return self._run_ssh_commands("process", step)
        if "file" in step_lower or "staging" in step_lower:
            return self._run_ssh_commands("file", step)
        if "network" in step_lower or "dns" in step_lower or "beacon" in step_lower:
            return self._run_ssh_commands("network", step)
        if (
            "cron" in step_lower
            or "startup" in step_lower
            or "service" in step_lower
            or "persistence" in step_lower
            or "scheduled" in step_lower
        ):
            return self._run_ssh_commands("persistence", step)
        return {"step": step, "status": "skipped", "reason": "no matching command set"}

    # ------------------------------------------------------------------
    # SSH execution
    # ------------------------------------------------------------------

    def _run_ssh_commands(self, category: str, step: str) -> Dict[str, Any]:
        ssh = self.tools.get("ssh_manager")
        host = self._ssh_host

        if ssh is None or host is None:
            return {
                "step": step,
                "status": "skipped",
                "reason": "ssh_manager not configured or no target host set",
            }

        if host not in ssh.get_connected_hosts():
            return {
                "step": step,
                "status": "skipped",
                "reason": f"no active SSH connection to {host}",
            }

        commands = _SSH_COMMANDS.get(category, [])
        raw_outputs: List[Dict[str, Any]] = []
        for cmd in commands:
            result = ssh.execute_command(host, cmd)
            raw_outputs.append(
                {
                    "command": cmd,
                    "stdout": result.stdout.strip(),
                    "stderr": result.stderr.strip(),
                    "exit_code": result.exit_code,
                }
            )

        evidence = [r for r in raw_outputs if (r["stdout"] or r["exit_code"] == 0)]
        return {
            "step": step,
            "status": "completed",
            "category": category,
            "host": host,
            "evidence": evidence,
        }

    # ------------------------------------------------------------------
    # Confidence and conclusion
    # ------------------------------------------------------------------

    def _calculate_confidence(self, findings: List[Dict]) -> float:
        if not findings:
            return 0.0
        completed = sum(1 for f in findings if f.get("status") == "completed")
        with_evidence = sum(
            1 for f in findings if f.get("status") == "completed" and f.get("evidence")
        )
        base = completed / len(findings)
        evidence_boost = (with_evidence / completed * 0.3) if completed else 0.0
        return round(min(base + evidence_boost, 1.0), 3)

    def _draw_conclusion(
        self,
        findings: List[Dict],
        evidence: List[Dict],
        confidence: float,
        attack_vector: str,
    ) -> str:
        if self.llm is not None and evidence:
            try:
                return self._llm_conclusion(findings, evidence, attack_vector)
            except Exception:
                pass

        if confidence >= 0.8:
            return "Hypothesis confirmed with high confidence"
        if confidence >= 0.5:
            return "Hypothesis partially confirmed — further investigation warranted"
        if confidence >= 0.2:
            return "Limited evidence found — hypothesis unlikely but not ruled out"
        return "No supporting evidence found — likely false positive"

    def _llm_conclusion(
        self, findings: List[Dict], evidence: List[Dict], attack_vector: str
    ) -> str:
        from raven.ai.lmstudio_client import AIMessage

        system = (
            "You are a security analyst. Given SSH forensic evidence collected "
            "during a threat investigation, write a concise conclusion (2–4 sentences). "
            "State whether the hypothesis is confirmed, partially confirmed, or a "
            "false positive, and cite specific evidence from the output. "
            "Do not invent findings that are not present in the data."
        )
        summary = {
            "attack_vector": attack_vector,
            "steps_completed": sum(
                1 for f in findings if f.get("status") == "completed"
            ),
            "steps_total": len(findings),
            "evidence_samples": [
                {
                    "command": e.get("command"),
                    "output_preview": e.get("stdout", "")[:400],
                }
                for e in evidence[:6]
            ],
        }
        user = json.dumps(summary, default=str)

        response = self.llm.chat(
            [
                AIMessage(role="system", content=system),
                AIMessage(role="user", content=user),
            ],
            temperature=0.0,
        )
        return response.content.strip()
