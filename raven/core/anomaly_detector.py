"""ML-based anomaly detection for zero-day threat identification"""

from typing import List, Dict, Any, Optional
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from dataclasses import dataclass
import pickle


@dataclass
class Anomaly:
    """Anomaly detection result"""
    anomaly_id: str
    anomaly_type: str
    severity: str
    confidence: float
    features: Dict[str, float]
    timestamp: float
    description: str


class AnomalyDetector:
    """ML-based anomaly detection using unsupervised learning"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.threshold = config.get("anomaly_threshold", 0.95)
        self.model = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names = []
        
    def train(self, normal_data: List[Dict[str, Any]]) -> None:
        """Train the anomaly detector on normal behavior data"""
        if not normal_data:
            raise ValueError("Training data cannot be empty")
        
        # Extract features
        features_matrix = self._extract_features(normal_data)
        
        # Fit scaler
        self.scaler.fit(features_matrix)
        scaled_features = self.scaler.transform(features_matrix)
        
        # Train model
        self.model.fit(scaled_features)
        self.is_trained = True
        self.feature_names = list(normal_data[0].keys())
        
    def detect(self, event_data: Dict[str, Any]) -> Optional[Anomaly]:
        """Detect if an event is anomalous"""
        if not self.is_trained:
            raise RuntimeError("Model must be trained before detection")
        
        # Extract and scale features
        features = self._extract_single_features(event_data)
        scaled_features = self.scaler.transform([features])
        
        # Get anomaly score
        anomaly_score = self.model.decision_function(scaled_features)[0]
        is_anomaly = self.model.predict(scaled_features)[0] == -1
        
        if is_anomaly and abs(anomaly_score) > self.threshold:
            return self._create_anomaly(event_data, anomaly_score)
        
        return None
    
    def _extract_features(self, data: List[Dict]) -> np.ndarray:
        """Extract feature matrix from data"""
        feature_keys = list(data[0].keys())
        features = []
        
        for item in data:
            row = []
            for key in feature_keys:
                value = item.get(key, 0)
                # Convert to float if possible
                try:
                    row.append(float(value))
                except (ValueError, TypeError):
                    row.append(0.0)
            features.append(row)
        
        return np.array(features)
    
    def _extract_single_features(self, data: Dict) -> List[float]:
        """Extract features from single event"""
        if not self.feature_names:
            raise RuntimeError("Feature names not set")
        
        features = []
        for key in self.feature_names:
            value = data.get(key, 0)
            try:
                features.append(float(value))
            except (ValueError, TypeError):
                features.append(0.0)
        
        return features
    
    def _create_anomaly(self, event_data: Dict, score: float) -> Anomaly:
        """Create anomaly object from detection result"""
        import time
        import uuid
        
        # Determine severity based on score
        if abs(score) > 0.8:
            severity = "critical"
        elif abs(score) > 0.6:
            severity = "high"
        elif abs(score) > 0.4:
            severity = "medium"
        else:
            severity = "low"
        
        # Identify anomaly type based on features
        anomaly_type = self._classify_anomaly_type(event_data)
        
        return Anomaly(
            anomaly_id=str(uuid.uuid4()),
            anomaly_type=anomaly_type,
            severity=severity,
            confidence=float(abs(score)),
            features=event_data,
            timestamp=time.time(),
            description=f"Anomaly detected with score {score:.3f}"
        )
    
    def _classify_anomaly_type(self, event_data: Dict) -> str:
        """Classify the type of anomaly based on features"""
        # Simple heuristic classification
        if "network" in str(event_data).lower():
            return "network_anomaly"
        elif "login" in str(event_data).lower():
            return "authentication_anomaly"
        elif "file" in str(event_data).lower():
            return "file_access_anomaly"
        elif "process" in str(event_data).lower():
            return "process_anomaly"
        else:
            return "unknown_anomaly"
    
    def save_model(self, path: str) -> None:
        """Save trained model to disk"""
        if not self.is_trained:
            raise RuntimeError("Model must be trained before saving")
        
        model_data = {
            "model": self.model,
            "scaler": self.scaler,
            "feature_names": self.feature_names,
            "threshold": self.threshold
        }
        
        with open(path, 'wb') as f:
            pickle.dump(model_data, f)
    
    def load_model(self, path: str) -> None:
        """Load trained model from disk.

        Refuses to deserialise unless ``settings.allow_pickle_models`` is
        explicitly enabled AND the resolved path stays under
        ``settings.model_path``. Closes VULN-4 (pickle RCE on
        attacker-controlled model files).
        """
        from pathlib import Path as _Path
        from raven.config import settings

        if not settings.allow_pickle_models:
            raise PermissionError(
                "pickle model loading is disabled. Set ALLOW_PICKLE_MODELS=true "
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

        with open(resolved, 'rb') as f:
            model_data = pickle.load(f)
        
        self.model = model_data["model"]
        self.scaler = model_data["scaler"]
        self.feature_names = model_data["feature_names"]
        self.threshold = model_data["threshold"]
        self.is_trained = True
