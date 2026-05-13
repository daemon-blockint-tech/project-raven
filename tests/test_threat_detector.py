"""Tests for threat detection engine"""

from raven.core.threat_detector import ThreatDetector, ThreatSeverity


def test_threat_detector_initialization():
    """Test threat detector initialization"""
    config = {"anomaly_threshold": 0.95}
    detector = ThreatDetector(config)

    assert detector is not None
    assert detector.config == config
    assert len(detector.detection_rules) > 0


def test_threat_analysis():
    """Test threat analysis"""
    config = {"anomaly_threshold": 0.95}
    detector = ThreatDetector(config)

    # Test event data
    event_data = {
        "failed_attempts": 6,
        "time_window": "5m",
        "unique_sources": 4,
        "affected_assets": ["server-1", "server-2"],
    }

    threats = detector.analyze(event_data)

    assert isinstance(threats, list)
    # Should detect at least one threat based on the rules
    assert len(threats) > 0


def test_rule_evaluation():
    """Test rule evaluation logic"""
    config = {"anomaly_threshold": 0.95}
    detector = ThreatDetector(config)

    rule = {
        "name": "test_rule",
        "type": "test",
        "severity": ThreatSeverity.HIGH,
        "conditions": {"failed_attempts": "> 5"},
    }

    # Should match
    event_data = {"failed_attempts": 6}
    assert detector._evaluate_rule(rule, event_data) == True

    # Should not match
    event_data = {"failed_attempts": 3}
    assert detector._evaluate_rule(rule, event_data) == False


def test_threat_creation():
    """Test threat object creation"""
    config = {"anomaly_threshold": 0.95}
    detector = ThreatDetector(config)

    rule = {
        "name": "test_rule",
        "type": "test",
        "severity": ThreatSeverity.HIGH,
        "conditions": {},
    }

    event_data = {"test": "data"}
    threat = detector._create_threat_from_rule(rule, event_data)

    assert threat.threat_id is not None
    assert threat.severity == ThreatSeverity.HIGH
    assert threat.source == "test_rule"
