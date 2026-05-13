"""AI-driven threat hypothesis generation"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import json
import time
import uuid


@dataclass
class ThreatHypothesis:
    """Threat hunting hypothesis"""
    hypothesis_id: str
    title: str
    description: str
    confidence: float
    priority: str
    attack_vector: str
    indicators: List[str]
    investigation_steps: List[str]
    created_at: float
    status: str  # pending, investigating, confirmed, false_positive


_KEYWORD_SIGNATURES = {
    "lateral_movement": {
        "keywords": ["smb", "rdp", "ssh", "winrm", "wmi", "psexec"],
        "title": "Potential Lateral Movement Activity",
        "description": "Indicators suggest possible lateral movement across the network",
        "confidence": 0.6,
        "priority": "high",
        "investigation_steps": [
            "Identify source and destination hosts",
            "Analyze authentication logs for failed/unusual logins",
            "Review SMB/RDP/SSH connection logs",
            "Check for credential reuse across hosts",
        ],
    },
    "data_exfiltration": {
        "keywords": ["upload", "exfil", "transfer", "ftp", "sftp", "large outbound"],
        "title": "Potential Data Exfiltration",
        "description": "Large or anomalous outbound data transfers detected",
        "confidence": 0.65,
        "priority": "critical",
        "investigation_steps": [
            "Identify data volumes and destination IPs",
            "Review file access logs for staging activity",
            "Check for compression or encryption of outbound data",
            "Correlate with user activity and access rights",
        ],
    },
    "persistence": {
        "keywords": ["registry", "startup", "scheduled", "cron", "service", "persistence"],
        "title": "Potential Persistence Mechanism",
        "description": "Indicators suggest attacker establishing persistence",
        "confidence": 0.55,
        "priority": "medium",
        "investigation_steps": [
            "Audit scheduled tasks and cron jobs for new entries",
            "Review startup items and autorun registry keys",
            "Check for new or modified system services",
            "Compare current configuration against known-good baseline",
        ],
    },
    "c2_communication": {
        "keywords": ["beacon", "callback", "dns tunnel", "irc", "http c2"],
        "title": "Potential Command and Control Communication",
        "description": "Network traffic patterns suggest C2 beaconing activity",
        "confidence": 0.65,
        "priority": "high",
        "investigation_steps": [
            "Analyse outbound connections for periodic beaconing intervals",
            "Inspect DNS queries for tunneling patterns (high entropy, unusually long labels)",
            "Block and sinkhole candidate C2 domains",
            "Capture and decode sample C2 traffic",
        ],
    },
}


class HypothesisGenerator:
    """Generate threat hunting hypotheses.

    When an LMStudioClient is provided at construction time, hypothesis
    generation is delegated to the local LLM.  The keyword-based classifier
    is retained as a synchronous fallback for when the LLM is unreachable.
    """

    def __init__(self, config: Dict[str, Any], llm_client: Optional[Any] = None):
        self.config = config
        self.llm = llm_client
        self.hypotheses: List[ThreatHypothesis] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_from_indicators(self, indicators: Dict[str, Any]) -> List[ThreatHypothesis]:
        """Generate hypotheses from security indicators.

        Tries LLM-based generation first; falls back to keyword matching on
        any exception (LLM unavailable, malformed JSON, timeout, etc.).
        """
        if self.llm is not None:
            try:
                hypotheses = self._generate_via_llm(indicators)
                if hypotheses:
                    self.hypotheses.extend(hypotheses)
                    return hypotheses
            except Exception:
                pass
        hypotheses = self._generate_via_keywords(indicators)
        self.hypotheses.extend(hypotheses)
        return hypotheses

    def get_hypothesis(self, hypothesis_id: str) -> Optional[ThreatHypothesis]:
        for h in self.hypotheses:
            if h.hypothesis_id == hypothesis_id:
                return h
        return None

    def update_hypothesis_status(self, hypothesis_id: str, status: str) -> bool:
        h = self.get_hypothesis(hypothesis_id)
        if h:
            h.status = status
            return True
        return False

    def list_hypotheses(self, status: Optional[str] = None) -> List[ThreatHypothesis]:
        if status:
            return [h for h in self.hypotheses if h.status == status]
        return self.hypotheses

    def prioritize_hypotheses(self) -> List[ThreatHypothesis]:
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return sorted(
            self.hypotheses,
            key=lambda h: (priority_order.get(h.priority, 99), -h.confidence),
        )

    # ------------------------------------------------------------------
    # LLM-based generation
    # ------------------------------------------------------------------

    def _generate_via_llm(self, indicators: Dict[str, Any]) -> List[ThreatHypothesis]:
        """Ask the local LLM to produce hypotheses as a JSON array.

        Expected LLM response schema (array of objects):
        [
          {
            "title": str,
            "description": str,
            "confidence": float,        // 0.0–1.0
            "priority": str,            // critical|high|medium|low
            "attack_vector": str,
            "investigation_steps": [str, ...]
          },
          ...
        ]
        """
        from raven.ai.lmstudio_client import AIMessage

        system = (
            "You are a threat intelligence analyst. "
            "Given a dict of security indicators, output a JSON array of threat "
            "hypotheses. Each hypothesis must have exactly these keys: "
            "title (str), description (str), confidence (float 0-1), "
            "priority (critical|high|medium|low), attack_vector (str), "
            "investigation_steps (array of str). "
            "Output ONLY the JSON array, no prose, no markdown fences."
        )
        user = json.dumps(indicators, default=str)

        response = self.llm.chat(
            [AIMessage(role="system", content=system),
             AIMessage(role="user", content=user)],
            temperature=0.1,
        )

        raw = response.content.strip()
        parsed = json.loads(raw)
        if not isinstance(parsed, list):
            parsed = [parsed]

        hypotheses = []
        for item in parsed:
            hypotheses.append(ThreatHypothesis(
                hypothesis_id=str(uuid.uuid4()),
                title=item["title"],
                description=item["description"],
                confidence=float(item.get("confidence", 0.5)),
                priority=item.get("priority", "medium"),
                attack_vector=item.get("attack_vector", "unknown"),
                indicators=list(indicators.keys()),
                investigation_steps=item.get("investigation_steps", []),
                created_at=time.time(),
                status="pending",
            ))
        return hypotheses

    # ------------------------------------------------------------------
    # Keyword fallback
    # ------------------------------------------------------------------

    def _generate_via_keywords(self, indicators: Dict[str, Any]) -> List[ThreatHypothesis]:
        indicator_str = str(indicators).lower()
        hypotheses = []
        for vector, sig in _KEYWORD_SIGNATURES.items():
            if any(kw in indicator_str for kw in sig["keywords"]):
                hypotheses.append(ThreatHypothesis(
                    hypothesis_id=str(uuid.uuid4()),
                    title=sig["title"],
                    description=sig["description"],
                    confidence=sig["confidence"],
                    priority=sig["priority"],
                    attack_vector=vector,
                    indicators=list(indicators.keys()),
                    investigation_steps=list(sig["investigation_steps"]),
                    created_at=time.time(),
                    status="pending",
                ))
        return hypotheses
