"""Behavioral profiling for baseline establishment and deviation detection"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from collections import defaultdict
import numpy as np
import time


@dataclass
class BehaviorProfile:
    """Behavior profile for an entity"""

    entity_id: str
    entity_type: str  # user, system, network, etc.
    baseline_features: Dict[str, Any]
    created_at: float
    updated_at: float
    sample_count: int


@dataclass
class BehaviorDeviation:
    """Deviation from established baseline"""

    deviation_id: str
    entity_id: str
    deviation_type: str
    severity: str
    baseline_value: float
    observed_value: float
    deviation_score: float
    timestamp: float
    description: str


class BehavioralProfiler:
    """Establish and monitor behavioral baselines"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.profiles: Dict[str, BehaviorProfile] = {}
        self.deviation_threshold = config.get(
            "deviation_threshold", 2.0
        )  # Standard deviations

    def create_profile(
        self, entity_id: str, entity_type: str, historical_data: List[Dict[str, Any]]
    ) -> BehaviorProfile:
        """Create a behavioral profile from historical data"""
        if not historical_data:
            raise ValueError("Historical data cannot be empty")

        # Calculate baseline statistics
        baseline = self._calculate_baseline(historical_data)

        profile = BehaviorProfile(
            entity_id=entity_id,
            entity_type=entity_type,
            baseline_features=baseline,
            created_at=time.time(),
            updated_at=time.time(),
            sample_count=len(historical_data),
        )

        self.profiles[entity_id] = profile
        return profile

    def update_profile(
        self, entity_id: str, new_data: List[Dict[str, Any]]
    ) -> BehaviorProfile:
        """Update existing profile with new data"""
        if entity_id not in self.profiles:
            raise ValueError(f"No profile exists for entity {entity_id}")

        profile = self.profiles[entity_id]

        # Recalculate baseline with updated data
        # In production, this would use incremental updates
        baseline = self._calculate_baseline(new_data)

        profile.baseline_features = baseline
        profile.updated_at = time.time()
        profile.sample_count += len(new_data)

        return profile

    def check_deviation(
        self, entity_id: str, current_data: Dict[str, Any]
    ) -> List[BehaviorDeviation]:
        """Check if current behavior deviates from baseline"""
        if entity_id not in self.profiles:
            raise ValueError(f"No profile exists for entity {entity_id}")

        profile = self.profiles[entity_id]
        deviations = []

        for feature, baseline_stats in profile.baseline_features.items():
            if feature not in current_data:
                continue

            current_value = current_data[feature]
            mean = baseline_stats["mean"]
            std = baseline_stats["std"]

            if std == 0:
                continue

            # Calculate z-score
            z_score = abs((current_value - mean) / std)

            if z_score > self.deviation_threshold:
                deviation = self._create_deviation(
                    entity_id, feature, mean, current_value, z_score
                )
                deviations.append(deviation)

        return deviations

    def _calculate_baseline(
        self, data: List[Dict[str, Any]]
    ) -> Dict[str, Dict[str, float]]:
        """Calculate baseline statistics from data"""
        # Aggregate all features across all data points
        feature_values = defaultdict(list)

        for item in data:
            for key, value in item.items():
                try:
                    feature_values[key].append(float(value))
                except (ValueError, TypeError):
                    pass

        # Calculate statistics for each feature
        baseline = {}
        for feature, values in feature_values.items():
            if len(values) > 0:
                values_array = np.array(values)
                baseline[feature] = {
                    "mean": float(np.mean(values_array)),
                    "std": float(np.std(values_array)),
                    "min": float(np.min(values_array)),
                    "max": float(np.max(values_array)),
                    "median": float(np.median(values_array)),
                    "count": len(values),
                }

        return baseline

    def _create_deviation(
        self,
        entity_id: str,
        feature: str,
        baseline: float,
        observed: float,
        score: float,
    ) -> BehaviorDeviation:
        """Create a deviation object"""
        import uuid

        # Determine severity
        if score > 4.0:
            severity = "critical"
        elif score > 3.0:
            severity = "high"
        elif score > 2.0:
            severity = "medium"
        else:
            severity = "low"

        return BehaviorDeviation(
            deviation_id=str(uuid.uuid4()),
            entity_id=entity_id,
            deviation_type=f"{feature}_deviation",
            severity=severity,
            baseline_value=baseline,
            observed_value=observed,
            deviation_score=score,
            timestamp=time.time(),
            description=f"{feature} deviates {score:.2f} standard deviations from baseline",
        )

    def get_profile(self, entity_id: str) -> Optional[BehaviorProfile]:
        """Get profile for an entity"""
        return self.profiles.get(entity_id)

    def list_profiles(self) -> List[BehaviorProfile]:
        """List all profiles"""
        return list(self.profiles.values())

    def delete_profile(self, entity_id: str) -> bool:
        """Delete a profile"""
        if entity_id in self.profiles:
            del self.profiles[entity_id]
            return True
        return False
