"""Advanced behavioral analysis for threat detection"""

from typing import List, Dict, Any, Optional
import numpy as np
from collections import defaultdict
from dataclasses import dataclass
import time


@dataclass
class BehaviorPattern:
    """Detected behavioral pattern"""
    pattern_id: str
    pattern_type: str
    entities: List[str]
    sequence: List[Dict[str, Any]]
    confidence: float
    risk_level: str
    first_seen: float
    last_seen: float
    description: str


class BehavioralAnalyzer:
    """Analyze behavioral patterns to detect threats"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.patterns: List[BehaviorPattern] = []
        self.entity_behaviors: Dict[str, List[Dict]] = defaultdict(list)
        
    def add_event(self, entity_id: str, event_data: Dict[str, Any]) -> None:
        """Add an event for an entity"""
        event_data['timestamp'] = event_data.get('timestamp', time.time())
        self.entity_behaviors[entity_id].append(event_data)
        
    def analyze_entity(self, entity_id: str) -> List[BehaviorPattern]:
        """Analyze behavior of a specific entity"""
        if entity_id not in self.entity_behaviors:
            return []
        
        events = self.entity_behaviors[entity_id]
        patterns = []
        
        # Check for various behavioral patterns
        if self._detect_suspicious_sequence(events):
            pattern = self._create_sequence_pattern(entity_id, events)
            patterns.append(pattern)
        
        if self._detect_anomalous_frequency(events):
            pattern = self._create_frequency_pattern(entity_id, events)
            patterns.append(pattern)
        
        if self._detect_lateral_movement(events):
            pattern = self._create_lateral_movement_pattern(entity_id, events)
            patterns.append(pattern)
        
        self.patterns.extend(patterns)
        return patterns
    
    def _detect_suspicious_sequence(self, events: List[Dict]) -> bool:
        """Detect suspicious event sequences"""
        if len(events) < 3:
            return False
        
        # Look for suspicious sequences like: recon -> exploit -> exfil
        sequence_types = [self._classify_event_type(e) for e in events]
        
        suspicious_sequences = [
            ['reconnaissance', 'exploitation', 'exfiltration'],
            ['reconnaissance', 'privilege_escalation', 'persistence'],
            ['initial_access', 'credential_theft', 'lateral_movement']
        ]
        
        for suspicious_seq in suspicious_sequences:
            if self._sequence_contains(sequence_types, suspicious_seq):
                return True
        
        return False
    
    def _detect_anomalous_frequency(self, events: List[Dict]) -> bool:
        """Detect anomalous event frequency"""
        if len(events) < 10:
            return False
        
        # Calculate event frequency
        timestamps = [e.get('timestamp', 0.0) for e in events]
        timestamps.sort()
        
        # Check for burst of events
        for i in range(len(timestamps) - 5):
            window_duration = timestamps[i+5] - timestamps[i]
            if window_duration < 10:  # 5 events in 10 seconds
                return True
        
        return False
    
    def _detect_lateral_movement(self, events: List[Dict]) -> bool:
        """Detect lateral movement patterns"""
        # Check for connections to multiple hosts
        destinations = set()
        for event in events:
            if 'destination' in event:
                destinations.add(event['destination'])
        
        return len(destinations) > 3
    
    def _classify_event_type(self, event: Dict) -> str:
        """Classify event type"""
        event_str = str(event).lower()
        
        if any(kw in event_str for kw in ['scan', 'recon', 'discover']):
            return 'reconnaissance'
        elif any(kw in event_str for kw in ['exploit', 'vuln', 'inject']):
            return 'exploitation'
        elif any(kw in event_str for kw in ['upload', 'transfer', 'exfil']):
            return 'exfiltration'
        elif any(kw in event_str for kw in ['privilege', 'escalate', 'sudo']):
            return 'privilege_escalation'
        elif any(kw in event_str for kw in ['persist', 'startup', 'registry']):
            return 'persistence'
        elif any(kw in event_str for kw in ['credential', 'password', 'hash']):
            return 'credential_theft'
        elif any(kw in event_str for kw in ['login', 'auth', 'access']):
            return 'initial_access'
        else:
            return 'unknown'
    
    def _sequence_contains(self, sequence: List[str], pattern: List[str]) -> bool:
        """Check if sequence contains pattern"""
        for i in range(len(sequence) - len(pattern) + 1):
            if sequence[i:i+len(pattern)] == pattern:
                return True
        return False
    
    def _create_sequence_pattern(self, entity_id: str, events: List[Dict]) -> BehaviorPattern:
        """Create a sequence-based pattern"""
        import uuid
        
        return BehaviorPattern(
            pattern_id=str(uuid.uuid4()),
            pattern_type="suspicious_sequence",
            entities=[entity_id],
            sequence=events,
            confidence=0.8,
            risk_level="high",
            first_seen=min(e['timestamp'] for e in events),
            last_seen=max(e['timestamp'] for e in events),
            description="Suspicious event sequence detected"
        )
    
    def _create_frequency_pattern(self, entity_id: str, events: List[Dict]) -> BehaviorPattern:
        """Create a frequency-based pattern"""
        import uuid
        
        return BehaviorPattern(
            pattern_id=str(uuid.uuid4()),
            pattern_type="anomalous_frequency",
            entities=[entity_id],
            sequence=events,
            confidence=0.7,
            risk_level="medium",
            first_seen=min(e['timestamp'] for e in events),
            last_seen=max(e['timestamp'] for e in events),
            description="Anomalous event frequency detected"
        )
    
    def _create_lateral_movement_pattern(self, entity_id: str, events: List[Dict]) -> BehaviorPattern:
        """Create a lateral movement pattern"""
        import uuid
        
        return BehaviorPattern(
            pattern_id=str(uuid.uuid4()),
            pattern_type="lateral_movement",
            entities=[entity_id],
            sequence=events,
            confidence=0.9,
            risk_level="critical",
            first_seen=min(e['timestamp'] for e in events),
            last_seen=max(e['timestamp'] for e in events),
            description="Lateral movement pattern detected"
        )
    
    def get_patterns(self, entity_id: Optional[str] = None) -> List[BehaviorPattern]:
        """Get detected patterns, optionally filtered by entity"""
        if entity_id:
            return [p for p in self.patterns if entity_id in p.entities]
        return self.patterns
    
    def clear_patterns(self) -> None:
        """Clear all detected patterns"""
        self.patterns.clear()
