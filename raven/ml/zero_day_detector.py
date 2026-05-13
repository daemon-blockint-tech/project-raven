"""Zero-day threat detection using advanced ML techniques"""

from typing import List, Dict, Any, Optional
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from dataclasses import dataclass
import joblib
import os
import time


@dataclass
class ZeroDayThreat:
    """Zero-day threat detection result"""
    threat_id: str
    threat_type: str
    confidence: float
    features: Dict[str, float]
    attack_pattern: str
    timestamp: float
    description: str
    recommended_actions: List[str]


class ZeroDayDetector:
    """Detect zero-day threats using ensemble ML methods"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.confidence_threshold = config.get("zero_day_confidence", 0.85)
        self.models = {}
        self.scalers = {}
        self.feature_keys: list = []
        self.is_trained = False
        
    def train(self, normal_data: List[Dict], attack_data: List[Dict]) -> None:
        """Train models on normal and attack patterns"""
        if not normal_data or not attack_data:
            raise ValueError("Both normal and attack data required for training")
        
        self.feature_keys = sorted(set(normal_data[0].keys()) | set(attack_data[0].keys()))

        normal_features = self._extract_features(normal_data)
        attack_features = self._extract_features(attack_data)

        isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        isolation_forest.fit(normal_features)
        
        # Train random forest for classification
        X = np.vstack([normal_features, attack_features])
        y = np.array([0] * len(normal_features) + [1] * len(attack_features))
        
        rf = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            max_depth=10
        )
        rf.fit(X, y)
        
        # Store models
        self.models['isolation_forest'] = isolation_forest
        self.models['random_forest'] = rf
        self.is_trained = True
        
    def detect(self, event_data: Dict[str, Any]) -> Optional[ZeroDayThreat]:
        """Detect if event represents a zero-day threat"""
        if not self.is_trained:
            raise RuntimeError("Models must be trained before detection")
        
        # Extract features
        features = self._extract_single_features(event_data)
        feature_array = np.array([features])
        
        # Get predictions from both models
        isolation_score = self.models['isolation_forest'].decision_function(feature_array)[0]
        rf_prediction = self.models['random_forest'].predict_proba(feature_array)[0]
        
        # Combine predictions
        is_anomaly = isolation_score < 0
        attack_probability = rf_prediction[1] if len(rf_prediction) > 1 else 0
        
        # Zero-day detection: high anomaly score but low known attack probability
        zero_day_score = abs(isolation_score) * (1 - attack_probability)
        
        if zero_day_score > self.confidence_threshold:
            return self._create_zero_day_threat(event_data, zero_day_score, features)
        
        return None
    
    def _extract_features(self, data: List[Dict]) -> np.ndarray:
        keys = self.feature_keys if self.feature_keys else sorted(data[0].keys())
        rows = []
        for item in data:
            row = []
            for key in keys:
                try:
                    row.append(float(item.get(key, 0)))
                except (ValueError, TypeError):
                    row.append(0.0)
            rows.append(row)
        return np.array(rows)

    def _extract_single_features(self, data: Dict) -> List[float]:
        keys = self.feature_keys if self.feature_keys else sorted(data.keys())
        features = []
        for key in keys:
            try:
                features.append(float(data.get(key, 0)))
            except (ValueError, TypeError):
                features.append(0.0)
        return features
    
    def _create_zero_day_threat(self, event_data: Dict, score: float, 
                                features: List[float]) -> ZeroDayThreat:
        """Create zero-day threat object"""
        import uuid
        
        # Classify attack pattern based on features
        attack_pattern = self._classify_attack_pattern(features, event_data)
        
        # Generate recommended actions
        actions = self._generate_recommended_actions(attack_pattern)
        
        return ZeroDayThreat(
            threat_id=str(uuid.uuid4()),
            threat_type="zero_day",
            confidence=float(score),
            features=dict(zip(event_data.keys(), features)),
            attack_pattern=attack_pattern,
            timestamp=time.time(),
            description=f"Zero-day threat detected with confidence {score:.3f}",
            recommended_actions=actions
        )
    
    def _classify_attack_pattern(self, features: List[float], event_data: Dict) -> str:
        """Classify the attack pattern based on features"""
        # Simple heuristic classification
        event_str = str(event_data).lower()
        
        if "network" in event_str or "connection" in event_str:
            return "network_exploitation"
        elif "file" in event_str or "process" in event_str:
            return "code_execution"
        elif "privilege" in event_str or "escalation" in event_str:
            return "privilege_escalation"
        elif "credential" in event_str or "auth" in event_str:
            return "credential_theft"
        else:
            return "unknown_pattern"
    
    def _generate_recommended_actions(self, attack_pattern: str) -> List[str]:
        """Generate recommended actions based on attack pattern"""
        actions_map = {
            "network_exploitation": [
                "Isolate affected host from network",
                "Block suspicious IP addresses",
                "Monitor for lateral movement",
                "Review firewall rules"
            ],
            "code_execution": [
                "Terminate suspicious processes",
                "Quarantine affected systems",
                "Scan for malicious files",
                "Review process execution logs"
            ],
            "privilege_escalation": [
                "Revoke elevated privileges",
                "Review user account changes",
                "Audit system modifications",
                "Reset affected credentials"
            ],
            "credential_theft": [
                "Force password resets",
                "Enable multi-factor authentication",
                "Review authentication logs",
                "Investigate credential dumping tools"
            ],
            "unknown_pattern": [
                "Isolate affected system",
                "Capture forensic evidence",
                "Monitor for additional activity",
                "Escalate to security team"
            ]
        }
        
        return actions_map.get(attack_pattern, actions_map["unknown_pattern"])
    
    def save_models(self, path: str) -> None:
        if not self.is_trained:
            raise RuntimeError("Models must be trained before saving")
        path = os.path.realpath(path)
        model_data = {
            "models": self.models,
            "feature_keys": self.feature_keys,
            "confidence_threshold": self.confidence_threshold,
        }
        joblib.dump(model_data, path)

    def load_models(self, path: str) -> None:
        """Load trained zero-day detection models.

        joblib uses pickle under the hood, so loading is RCE-equivalent on
        attacker-controlled files. Requires ``settings.allow_pickle_models``
        + the path to live under ``settings.model_path``. Closes VULN-4.
        """
        from pathlib import Path as _Path
        from raven.config import settings

        if not settings.allow_pickle_models:
            raise PermissionError(
                "joblib model loading is disabled. Set ALLOW_PICKLE_MODELS=true "
                "and confirm every file under MODEL_PATH is trusted."
            )
        resolved = _Path(path).resolve(strict=False)
        root = _Path(settings.model_path).resolve()
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise PermissionError(
                f"refusing to load model outside MODEL_PATH ({root}): {path}"
            ) from exc
        if not resolved.is_file():
            raise FileNotFoundError(f"Model file not found: {resolved}")
        model_data = joblib.load(str(resolved))
        self.models = model_data["models"]
        self.feature_keys = model_data.get("feature_keys", [])
        self.confidence_threshold = model_data["confidence_threshold"]
        self.is_trained = True
