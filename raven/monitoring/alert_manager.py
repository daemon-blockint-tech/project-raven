"""Alert management and prioritization"""

from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import time
import uuid


class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(Enum):
    """Alert status"""
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    ESCALATED = "escalated"


@dataclass
class Alert:
    """Security alert"""
    alert_id: str
    title: str
    description: str
    severity: AlertSeverity
    status: AlertStatus
    source: str
    created_at: float
    updated_at: float
    metadata: Dict[str, Any]
    assigned_to: Optional[str] = None
    resolved_at: Optional[float] = None


class AlertManager:
    """Manage security alerts"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.alerts: List[Alert] = []
        self.alert_handlers: Dict[str, Callable] = {}
        
    def create_alert(self, title: str, description: str, severity: AlertSeverity,
                   source: str, metadata: Optional[Dict[str, Any]] = None) -> Alert:
        """Create a new alert"""
        alert = Alert(
            alert_id=str(uuid.uuid4()),
            title=title,
            description=description,
            severity=severity,
            status=AlertStatus.OPEN,
            source=source,
            created_at=time.time(),
            updated_at=time.time(),
            metadata=metadata or {}
        )
        
        self.alerts.append(alert)
        
        # Trigger handlers
        self._trigger_handlers(alert)
        
        return alert
    
    def acknowledge_alert(self, alert_id: str, user: str) -> bool:
        """Acknowledge an alert"""
        alert = self.get_alert(alert_id)
        if alert:
            alert.status = AlertStatus.ACKNOWLEDGED
            alert.assigned_to = user
            alert.updated_at = time.time()
            return True
        return False
    
    def resolve_alert(self, alert_id: str) -> bool:
        """Resolve an alert"""
        alert = self.get_alert(alert_id)
        if alert:
            alert.status = AlertStatus.RESOLVED
            alert.resolved_at = time.time()
            alert.updated_at = time.time()
            return True
        return False
    
    def escalate_alert(self, alert_id: str) -> bool:
        """Escalate an alert"""
        alert = self.get_alert(alert_id)
        if alert:
            alert.status = AlertStatus.ESCALATED
            alert.updated_at = time.time()
            return True
        return False
    
    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Get a specific alert"""
        for alert in self.alerts:
            if alert.alert_id == alert_id:
                return alert
        return None
    
    def list_alerts(self, status: Optional[AlertStatus] = None,
                   severity: Optional[AlertSeverity] = None,
                   limit: int = 100) -> List[Alert]:
        """List alerts with optional filters"""
        filtered = self.alerts
        
        if status:
            filtered = [a for a in filtered if a.status == status]
        
        if severity:
            filtered = [a for a in filtered if a.severity == severity]
        
        # Sort by creation time (newest first)
        filtered.sort(key=lambda a: a.created_at, reverse=True)
        
        return filtered[:limit]
    
    def get_open_alerts(self) -> List[Alert]:
        """Get all open alerts"""
        return self.list_alerts(status=AlertStatus.OPEN)
    
    def get_critical_alerts(self) -> List[Alert]:
        """Get all critical alerts"""
        return self.list_alerts(severity=AlertSeverity.CRITICAL)
    
    def register_handler(self, severity: AlertSeverity, handler: Callable) -> None:
        """Register a handler for alerts of a specific severity"""
        self.alert_handlers[severity.value] = handler
    
    def _trigger_handlers(self, alert: Alert) -> None:
        """Trigger handlers for an alert"""
        handler = self.alert_handlers.get(alert.severity.value)
        if handler:
            try:
                handler(alert)
            except Exception as e:
                print(f"Handler error: {e}")
    
    def get_alert_summary(self) -> Dict[str, Any]:
        """Get alert summary statistics"""
        total = len(self.alerts)
        open_count = len([a for a in self.alerts if a.status == AlertStatus.OPEN])
        resolved_count = len([a for a in self.alerts if a.status == AlertStatus.RESOLVED])
        
        severity_counts = {}
        for severity in AlertSeverity:
            count = len([a for a in self.alerts if a.severity == severity])
            severity_counts[severity.value] = count
        
        return {
            "total": total,
            "open": open_count,
            "resolved": resolved_count,
            "by_severity": severity_counts,
            "avg_resolution_time": self._calculate_avg_resolution_time()
        }
    
    def _calculate_avg_resolution_time(self) -> float:
        """Calculate average resolution time"""
        resolved = [a for a in self.alerts if a.resolved_at]
        if not resolved:
            return 0.0
        
        resolution_times = [a.resolved_at - a.created_at for a in resolved]
        return sum(resolution_times) / len(resolution_times)
