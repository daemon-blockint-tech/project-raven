"""Main threat hunting orchestrator"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import time
from raven.ml.code_flow_scanner import CodeFlowScanner, ScanReport


@dataclass
class HuntingSession:
    """A threat hunting session"""

    session_id: str
    start_time: float
    end_time: Optional[float]
    hypotheses_generated: int
    investigations_completed: int
    threats_found: int
    status: str


class ThreatHunter:
    """Orchestrate proactive threat hunting operations"""

    def __init__(
        self,
        config: Dict[str, Any],
        hypothesis_generator: Any,
        investigator: Any,
        tools: Dict[str, Any],
    ):
        self.config = config
        self.hypothesis_generator = hypothesis_generator
        self.investigator = investigator
        self.tools = tools
        self.sessions: List[HuntingSession] = []
        self.active_session: Optional[HuntingSession] = None
        self.code_scanner = CodeFlowScanner(config)

    def start_hunt(self, indicators: Dict[str, Any]) -> HuntingSession:
        """Start a new threat hunting session"""
        import uuid

        session = HuntingSession(
            session_id=str(uuid.uuid4()),
            start_time=time.time(),
            end_time=None,
            hypotheses_generated=0,
            investigations_completed=0,
            threats_found=0,
            status="active",
        )

        self.active_session = session
        self.sessions.append(session)

        # Generate hypotheses
        hypotheses = self.hypothesis_generator.generate_from_indicators(indicators)
        session.hypotheses_generated = len(hypotheses)

        # Prioritize and investigate
        prioritized = self.hypothesis_generator.prioritize_hypotheses()

        for hypothesis in prioritized[:5]:  # Limit to top 5 for now
            self.hypothesis_generator.update_hypothesis_status(
                hypothesis.hypothesis_id, "investigating"
            )

            result = self.investigator.investigate(hypothesis.hypothesis_id, hypothesis)
            session.investigations_completed += 1

            # Update hypothesis status based on investigation
            if result.confidence > 0.7:
                self.hypothesis_generator.update_hypothesis_status(
                    hypothesis.hypothesis_id, "confirmed"
                )
                session.threats_found += 1
            elif result.confidence < 0.3:
                self.hypothesis_generator.update_hypothesis_status(
                    hypothesis.hypothesis_id, "false_positive"
                )
            else:
                self.hypothesis_generator.update_hypothesis_status(
                    hypothesis.hypothesis_id, "pending"
                )

        session.end_time = time.time()
        session.status = "completed"
        self.active_session = None

        return session

    def get_session(self, session_id: str) -> Optional[HuntingSession]:
        """Get a specific hunting session"""
        for session in self.sessions:
            if session.session_id == session_id:
                return session
        return None

    def list_sessions(self) -> List[HuntingSession]:
        """List all hunting sessions"""
        return self.sessions

    def get_active_hypotheses(self) -> List[Any]:
        """Get currently active hypotheses"""
        return self.hypothesis_generator.list_hypotheses(status="pending")

    def get_confirmed_threats(self) -> List[Any]:
        """Get confirmed threats from hunting"""
        return self.hypothesis_generator.list_hypotheses(status="confirmed")

    def generate_hunting_report(self, session_id: str) -> Dict[str, Any]:
        """Generate a comprehensive hunting report"""
        session = self.get_session(session_id)
        if not session:
            return {"error": "Session not found"}

        hypotheses = self.hypothesis_generator.list_hypotheses()

        report = {
            "session_id": session.session_id,
            "duration": session.end_time - session.start_time
            if session.end_time
            else 0,
            "hypotheses_generated": session.hypotheses_generated,
            "investigations_completed": session.investigations_completed,
            "threats_found": session.threats_found,
            "status": session.status,
            "hypotheses": [
                {
                    "id": h.hypothesis_id,
                    "title": h.title,
                    "status": h.status,
                    "confidence": h.confidence,
                    "priority": h.priority,
                }
                for h in hypotheses
            ],
        }

        return report

    def code_hunt(self, repo_path: str) -> Dict[str, Any]:
        """
        Defensively scan a codebase for exploitable taint flows using the same
        technique threat actors use offensively (ZenoX report, Jan 2025).
        Traces user-input to dangerous-sink paths across LFI/AFO/RCE/XSS/SQLI/SSRF/IDOR.
        """
        scan: ScanReport = self.code_scanner.scan_repository(repo_path)

        high_confidence = [
            {
                "flow_id": f.flow_id,
                "vuln_class": f.vuln_class.value,
                "confidence": round(f.confidence, 2),
                "file": f.file_path,
                "source_line": f.line_start,
                "sink_line": f.line_end,
                "source": f.source,
                "sink": f.sink,
                "shared_vars": f.path,
                "description": f.description,
                "poc_hint": f.poc_hint,
            }
            for f in scan.taint_flows
            if f.confidence >= 0.8
        ]

        return {
            "report_id": scan.report_id,
            "target": scan.target_path,
            "files_scanned": scan.files_scanned,
            "total_flows": len(scan.taint_flows),
            "high_confidence_flows": scan.high_confidence_count,
            "scan_duration_seconds": round(scan.scan_duration, 2),
            "findings": high_confidence,
        }
