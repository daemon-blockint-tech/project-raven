"""Core threat detection engine"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
import numpy as np


class ThreatSeverity(Enum):
    """Threat severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(Enum):
    """Types of threats"""
    MALWARE = "malware"
    PHISHING = "phishing"
    DOS = "denial_of_service"
    INTRUSION = "intrusion"
    DATA_EXFILTRATION = "data_exfiltration"
    ZERO_DAY = "zero_day"
    CVE_EXPLOIT = "cve_exploit"
    UNKNOWN = "unknown"


@dataclass
class Threat:
    """Threat data structure"""
    threat_id: str
    threat_type: ThreatType
    severity: ThreatSeverity
    confidence: float
    source: str
    timestamp: float
    indicators: Dict[str, Any]
    affected_assets: List[str]
    description: str
    metadata: Optional[Dict[str, Any]] = None
    cve_id: Optional[str] = None


class ThreatDetector:
    """Main threat detection engine"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.detection_rules = self._load_detection_rules()
        # Integration with CVE matcher for instant vulnerability recognition
        from raven.ml.cve_matcher import CVEMatcher
        self.cve_matcher = CVEMatcher(config)
        
    def _load_detection_rules(self) -> List[Dict]:
        """Load detection rules from configuration"""
        # In production, load from database or config files
        return [
            {
                "name": "suspicious_login_pattern",
                "type": "behavioral",
                "severity": ThreatSeverity.HIGH,
                "conditions": {
                    "failed_attempts": "> 5",
                    "time_window": "5m",
                    "unique_sources": "> 3"
                }
            },
            {
                "name": "port_scan_detection",
                "type": "network",
                "severity": ThreatSeverity.MEDIUM,
                "conditions": {
                    "ports_scanned": "> 10",
                    "time_window": "1m"
                }
            },
            {
                "name": "data_exfiltration",
                "type": "data",
                "severity": ThreatSeverity.CRITICAL,
                "conditions": {
                    "volume_outbound": "> 1GB",
                    "time_window": "10m"
                }
            }
        ]
    
    def analyze(self, event_data: Dict[str, Any], code_context: Optional[str] = None) -> List[Threat]:
        """Analyze event data for threats"""
        threats = []
        
        # Rule-based detection
        for rule in self.detection_rules:
            if self._evaluate_rule(rule, event_data):
                threat = self._create_threat_from_rule(rule, event_data)
                threats.append(threat)
        
        # CVE-based detection (instant vulnerability recognition)
        if code_context:
            cve_threat = self._check_for_cve(code_context, event_data)
            if cve_threat:
                threats.append(cve_threat)
        
        # ML-based detection (placeholder)
        ml_threats = self._ml_analyze(event_data)
        threats.extend(ml_threats)
        
        return threats
    
    def _check_for_cve(self, code: str, event_data: Dict) -> Optional[Threat]:
        """Check for known CVE vulnerabilities in code"""
        import time
        import uuid
        
        version_info = event_data.get("version_info", {})
        cve = self.cve_matcher.recognize_cve(code, version_info)
        
        if cve:
            return Threat(
                threat_id=str(uuid.uuid4()),
                threat_type=ThreatType.CVE_EXPLOIT,
                severity=ThreatSeverity.CRITICAL if cve.severity == "critical" else ThreatSeverity.HIGH,
                confidence=cve.cvss_score / 10.0,
                source="cve_matcher",
                timestamp=time.time(),
                indicators={"cve_id": cve.cve_id, "description": cve.description},
                affected_assets=event_data.get("affected_assets", []),
                description=f"CVE vulnerability detected: {cve.cve_id}",
                cve_id=cve.cve_id
            )
        
        return None
    
    def _evaluate_rule(self, rule: Dict, event_data: Dict) -> bool:
        """Evaluate if event data matches a rule"""
        conditions = rule.get("conditions", {})
        
        # Simple condition evaluation (in production, use more sophisticated logic)
        for key, value in conditions.items():
            if key not in event_data:
                continue
            
            # Parse condition (e.g., "> 5" -> greater than 5)
            if isinstance(value, str) and value.startswith(">"):
                threshold = float(value[1:].strip())
                if not (event_data[key] > threshold):
                    return False
        
        return True
    
    def _create_threat_from_rule(self, rule: Dict, event_data: Dict) -> Threat:
        """Create a threat object from a matched rule"""
        import time
        import uuid
        
        return Threat(
            threat_id=str(uuid.uuid4()),
            threat_type=ThreatType.UNKNOWN,
            severity=rule["severity"],
            confidence=0.8,
            source=rule["name"],
            timestamp=time.time(),
            indicators=event_data,
            affected_assets=event_data.get("affected_assets", []),
            description=f"Threat detected by rule: {rule['name']}",
            metadata={"rule_type": rule["type"]}
        )
    
    def _ml_analyze(self, event_data: Dict) -> List[Threat]:
        """ML-based threat analysis (placeholder for ML integration)"""
        # This will be implemented with actual ML models
        return []
    
    def correlate_threats(self, threats: List[Threat]) -> List[Threat]:
        """Correlate related threats into attack chains"""
        # Group threats by time window and affected assets
        # Identify attack patterns and chains
        return threats
