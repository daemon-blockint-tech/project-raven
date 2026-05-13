"""Sequence analysis for log and event pattern detection"""

from typing import List, Dict, Any, Optional
from collections import Counter
from dataclasses import dataclass


@dataclass
class SequenceMatch:
    """Matched sequence pattern"""

    pattern_id: str
    pattern_type: str
    matched_sequence: List[str]
    confidence: float
    context: Dict[str, Any]
    timestamp: float


class SequenceAnalyzer:
    """Analyze sequences of events/logs for attack patterns"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.patterns = self._load_attack_patterns()

    def _load_attack_patterns(self) -> Dict[str, List[str]]:
        """Load known attack sequence patterns"""
        return {
            "brute_force": [
                "failed_login",
                "failed_login",
                "failed_login",
                "failed_login",
                "failed_login",
                "successful_login",
            ],
            "privilege_escalation": [
                "login",
                "enum_users",
                "exploit_vuln",
                "gain_privilege",
            ],
            "data_exfiltration": [
                "access_sensitive_file",
                "compress_data",
                "initiate_transfer",
                "complete_transfer",
            ],
            "persistence": [
                "initial_access",
                "create_backdoor",
                "schedule_task",
                "verify_persistence",
            ],
        }

    def analyze_log_sequence(self, logs: List[str]) -> List[SequenceMatch]:
        """Analyze a sequence of log entries"""
        matches = []

        # Parse logs into event types
        event_types = [self._classify_log(log) for log in logs]

        # Check for pattern matches
        for pattern_name, pattern in self.patterns.items():
            match = self._find_pattern_match(event_types, pattern, pattern_name)
            if match:
                matches.append(match)

        return matches

    def _classify_log(self, log: str) -> str:
        """Classify a log entry into event type"""
        log_lower = log.lower()

        # Simple keyword-based classification
        if "failed" in log_lower and "login" in log_lower:
            return "failed_login"
        elif "successful" in log_lower and "login" in log_lower:
            return "successful_login"
        elif "ssh" in log_lower or "rdp" in log_lower:
            return "remote_access"
        elif "privilege" in log_lower or "sudo" in log_lower:
            return "privilege_escalation"
        elif "file" in log_lower and "access" in log_lower:
            return "access_sensitive_file"
        elif "upload" in log_lower or "transfer" in log_lower:
            return "initiate_transfer"
        elif "schedule" in log_lower or "cron" in log_lower:
            return "schedule_task"
        elif "service" in log_lower and "start" in log_lower:
            return "create_backdoor"
        else:
            return "unknown"

    def _find_pattern_match(
        self, sequence: List[str], pattern: List[str], pattern_name: str
    ) -> Optional[SequenceMatch]:
        """Find if pattern exists in sequence"""
        import time

        for i in range(len(sequence) - len(pattern) + 1):
            subsequence = sequence[i : i + len(pattern)]

            # Check for partial match (allow some mismatches)
            matches = sum(1 for a, b in zip(subsequence, pattern) if a == b)
            confidence = matches / len(pattern)

            if confidence >= 0.7:  # 70% match threshold
                return SequenceMatch(
                    pattern_id=f"{pattern_name}_{i}",
                    pattern_type=pattern_name,
                    matched_sequence=subsequence,
                    confidence=confidence,
                    context={"position": i, "length": len(pattern)},
                    timestamp=time.time(),
                )

        return None

    def detect_anomalous_sequences(
        self, sequences: List[List[str]]
    ) -> List[Dict[str, Any]]:
        """Detect sequences that deviate from normal patterns"""
        anomalies = []

        # Calculate sequence statistics
        all_sequences = [tuple(seq) for seq in sequences]
        sequence_counts = Counter(all_sequences)

        # Find rare sequences
        total = len(all_sequences)
        if total == 0:
            return anomalies
        for seq, count in sequence_counts.items():
            frequency = count / total
            if frequency < 0.01:  # Less than 1% occurrence
                anomalies.append(
                    {
                        "sequence": list(seq),
                        "frequency": frequency,
                        "occurrence_count": count,
                        "anomaly_type": "rare_sequence",
                    }
                )

        return anomalies

    def extract_patterns_from_sequences(
        self, sequences: List[List[str]], min_support: float = 0.1
    ) -> List[List[str]]:
        """Extract common patterns from sequences using simple frequency analysis"""
        pattern_counts = Counter()

        for seq in sequences:
            # Extract all subsequences of length 2-4
            for length in range(2, min(5, len(seq) + 1)):
                for i in range(len(seq) - length + 1):
                    pattern = tuple(seq[i : i + length])
                    pattern_counts[pattern] += 1

        total = len(sequences)
        if total == 0:
            return []
        common_patterns = [
            list(pattern)
            for pattern, count in pattern_counts.items()
            if count / total >= min_support
        ]

        return common_patterns
