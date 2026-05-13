"""Metrics collection and aggregation"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from collections import defaultdict
import time
from prometheus_client import Counter, Gauge, Histogram, start_http_server


@dataclass
class Metric:
    """Metric data point"""

    name: str
    value: float
    labels: Dict[str, str]
    timestamp: float


class MetricsCollector:
    """Collect and aggregate system metrics"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enable_metrics = config.get("enable_metrics", True)
        self.metrics_port = config.get("metrics_port", 9090)

        # Prometheus metrics
        if self.enable_metrics:
            self._init_prometheus_metrics()

        # Internal metric storage
        self.metrics_history: Dict[str, List[Metric]] = defaultdict(list)

    def _init_prometheus_metrics(self):
        """Initialize Prometheus metrics"""
        self.threats_detected = Counter(
            "raven_threats_detected_total",
            "Total number of threats detected",
            ["severity", "type"],
        )

        self.threats_blocked = Counter(
            "raven_threats_blocked_total", "Total number of threats blocked", ["method"]
        )

        self.detection_time = Histogram(
            "raven_detection_duration_seconds", "Time taken to detect threats"
        )

        self.active_hypotheses = Gauge(
            "raven_active_hypotheses", "Number of active threat hunting hypotheses"
        )

        self.system_health = Gauge("raven_system_health", "System health score (0-100)")

        # Start Prometheus server
        try:
            start_http_server(self.metrics_port)
        except Exception as e:
            print(f"Failed to start Prometheus server: {e}")

    def record_threat_detected(self, severity: str, threat_type: str):
        """Record a threat detection"""
        if self.enable_metrics:
            self.threats_detected.labels(severity=severity, type=threat_type).inc()

        self._store_metric(
            "threats_detected", 1.0, {"severity": severity, "type": threat_type}
        )

    def record_threat_blocked(self, method: str):
        """Record a threat blocked"""
        if self.enable_metrics:
            self.threats_blocked.labels(method=method).inc()

        self._store_metric("threats_blocked", 1.0, {"method": method})

    def record_detection_time(self, duration: float):
        """Record detection time"""
        if self.enable_metrics:
            self.detection_time.observe(duration)

        self._store_metric("detection_time", duration, {})

    def update_active_hypotheses(self, count: int):
        """Update active hypotheses count"""
        if self.enable_metrics:
            self.active_hypotheses.set(count)

        self._store_metric("active_hypotheses", float(count), {})

    def update_system_health(self, score: float):
        """Update system health score"""
        if self.enable_metrics:
            self.system_health.set(score)

        self._store_metric("system_health", score, {})

    def _store_metric(self, name: str, value: float, labels: Dict[str, str]):
        """Store metric in history"""
        metric = Metric(name=name, value=value, labels=labels, timestamp=time.time())
        self.metrics_history[name].append(metric)

        # Keep only last 1000 metrics per name
        if len(self.metrics_history[name]) > 1000:
            self.metrics_history[name] = self.metrics_history[name][-1000:]

    def get_metrics(
        self, metric_name: str, since: Optional[float] = None
    ) -> List[Metric]:
        """Get metrics for a specific name"""
        metrics = self.metrics_history.get(metric_name, [])

        if since:
            metrics = [m for m in metrics if m.timestamp >= since]

        return metrics

    def get_summary(self) -> Dict[str, Any]:
        """Get metrics summary"""
        summary = {
            "threats_detected": {
                "total": sum(
                    m.value for m in self.metrics_history.get("threats_detected", [])
                ),
                "by_severity": self._aggregate_by_label("threats_detected", "severity"),
                "by_type": self._aggregate_by_label("threats_detected", "type"),
            },
            "threats_blocked": {
                "total": sum(
                    m.value for m in self.metrics_history.get("threats_blocked", [])
                ),
                "by_method": self._aggregate_by_label("threats_blocked", "method"),
            },
            "detection_time": {
                "avg": self._average_metric("detection_time"),
                "max": self._max_metric("detection_time"),
            },
            "system_health": self._latest_metric("system_health"),
            "active_hypotheses": self._latest_metric("active_hypotheses"),
        }

        return summary

    def _aggregate_by_label(self, metric_name: str, label_key: str) -> Dict[str, float]:
        """Aggregate metrics by label"""
        metrics = self.metrics_history.get(metric_name, [])
        aggregated = defaultdict(float)

        for metric in metrics:
            label_value = metric.labels.get(label_key, "unknown")
            aggregated[label_value] += metric.value

        return dict(aggregated)

    def _average_metric(self, metric_name: str) -> float:
        """Calculate average of a metric"""
        metrics = self.metrics_history.get(metric_name, [])
        if not metrics:
            return 0.0

        values = [m.value for m in metrics]
        return sum(values) / len(values)

    def _max_metric(self, metric_name: str) -> float:
        """Get maximum value of a metric"""
        metrics = self.metrics_history.get(metric_name, [])
        if not metrics:
            return 0.0

        return max(m.value for m in metrics)

    def _latest_metric(self, metric_name: str) -> Optional[float]:
        """Get latest value of a metric"""
        metrics = self.metrics_history.get(metric_name, [])
        if not metrics:
            return None

        return metrics[-1].value
