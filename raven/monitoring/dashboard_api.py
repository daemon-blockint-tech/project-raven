"""Dashboard API for monitoring interface"""

from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import time


class DashboardAPI:
    """Dashboard API for monitoring and visualization"""
    
    def __init__(self, config: Dict[str, Any], metrics_collector: Any, 
                 alert_manager: Any):
        self.config = config
        self.metrics = metrics_collector
        self.alerts = alert_manager
        self.app = FastAPI(title="Project Raven Dashboard")
        self._setup_routes()
        
    def _setup_routes(self):
        """Setup API routes"""
        
        @self.app.get("/")
        async def root():
            return {"message": "Project Raven Dashboard API", "version": "0.1.0"}
        
        @self.app.get("/metrics")
        async def get_metrics():
            """Get system metrics"""
            return self.metrics.get_summary()
        
        @self.app.get("/alerts")
        async def get_alerts(status: Optional[str] = None, 
                            severity: Optional[str] = None,
                            limit: int = 100):
            """Get alerts"""
            from raven.monitoring.alert_manager import AlertSeverity, AlertStatus
            
            status_enum = AlertStatus(status) if status else None
            severity_enum = AlertSeverity(severity) if severity else None
            
            alerts = self.alerts.list_alerts(
                status=status_enum,
                severity=severity_enum,
                limit=limit
            )
            
            return {
                "alerts": [
                    {
                        "id": a.alert_id,
                        "title": a.title,
                        "description": a.description,
                        "severity": a.severity.value,
                        "status": a.status.value,
                        "source": a.source,
                        "created_at": a.created_at,
                        "assigned_to": a.assigned_to
                    }
                    for a in alerts
                ]
            }
        
        @self.app.get("/alerts/summary")
        async def get_alert_summary():
            """Get alert summary"""
            return self.alerts.get_alert_summary()
        
        @self.app.get("/threat-map")
        async def get_threat_map():
            """Get threat map data"""
            return {
                "threats": self._generate_threat_map_data(),
                "timestamp": time.time()
            }
        
        @self.app.get("/health")
        async def health_check():
            """Health check endpoint"""
            return {
                "status": "healthy",
                "timestamp": time.time(),
                "components": {
                    "metrics": "operational",
                    "alerts": "operational",
                    "detector": "operational"
                }
            }
    
    def _generate_threat_map_data(self) -> List[Dict[str, Any]]:
        """Generate threat map visualization data"""
        # Placeholder for actual threat map data
        return [
            {
                "id": "threat-1",
                "type": "zero_day",
                "severity": "critical",
                "location": "network-segment-a",
                "status": "active",
                "confidence": 0.95
            },
            {
                "id": "threat-2",
                "type": "lateral_movement",
                "severity": "high",
                "location": "network-segment-b",
                "status": "mitigating",
                "confidence": 0.85
            }
        ]
    
    def get_app(self) -> FastAPI:
        """Get the FastAPI application"""
        return self.app
