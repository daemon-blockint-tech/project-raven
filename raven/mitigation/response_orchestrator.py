"""Response orchestrator for coordinated mitigation actions"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import time


@dataclass
class ResponsePlan:
    """Coordinated response plan"""

    plan_id: str
    threat_id: str
    severity: str
    actions: List[Dict[str, Any]]
    execution_order: List[str]
    created_at: float
    status: str


@dataclass
class ResponseExecution:
    """Execution of a response plan"""

    execution_id: str
    plan_id: str
    results: List[Any]
    success: bool
    execution_time: float
    timestamp: float


class ResponseOrchestrator:
    """Orchestrate coordinated response actions"""

    def __init__(self, config: Dict[str, Any], containment: Any, remediation: Any):
        self.config = config
        self.containment = containment
        self.remediation = remediation
        self.plans: List[ResponsePlan] = []
        self.executions: List[ResponseExecution] = []

    def create_response_plan(self, threat: Any, threat_type: str) -> ResponsePlan:
        """Create a response plan based on threat"""
        import uuid

        # Determine actions based on threat type and severity
        actions = self._generate_response_actions(threat, threat_type)

        plan = ResponsePlan(
            plan_id=str(uuid.uuid4()),
            threat_id=getattr(threat, "threat_id", str(uuid.uuid4())),
            severity=getattr(threat, "severity", "medium"),
            actions=actions,
            execution_order=self._determine_execution_order(actions),
            created_at=time.time(),
            status="pending",
        )

        self.plans.append(plan)
        return plan

    def _generate_response_actions(
        self, threat: Any, threat_type: str
    ) -> List[Dict[str, Any]]:
        """Generate appropriate response actions"""
        actions = []

        if threat_type == "zero_day":
            actions.extend(
                [
                    {
                        "type": "containment",
                        "action": "isolate_host",
                        "priority": "critical",
                    },
                    {"type": "containment", "action": "block_ip", "priority": "high"},
                    {
                        "type": "remediation",
                        "action": "harden_configuration",
                        "priority": "medium",
                    },
                    {
                        "type": "remediation",
                        "action": "rotate_credentials",
                        "priority": "medium",
                    },
                ]
            )
        elif threat_type == "lateral_movement":
            actions.extend(
                [
                    {
                        "type": "containment",
                        "action": "isolate_host",
                        "priority": "critical",
                    },
                    {
                        "type": "containment",
                        "action": "disable_account",
                        "priority": "high",
                    },
                    {
                        "type": "remediation",
                        "action": "update_firewall_rules",
                        "priority": "medium",
                    },
                ]
            )
        elif threat_type == "data_exfiltration":
            actions.extend(
                [
                    {
                        "type": "containment",
                        "action": "block_ip",
                        "priority": "critical",
                    },
                    {
                        "type": "containment",
                        "action": "terminate_process",
                        "priority": "high",
                    },
                    {
                        "type": "remediation",
                        "action": "rotate_credentials",
                        "priority": "medium",
                    },
                ]
            )
        else:
            # Default response
            actions.extend(
                [
                    {
                        "type": "containment",
                        "action": "isolate_host",
                        "priority": "high",
                    },
                    {
                        "type": "remediation",
                        "action": "harden_configuration",
                        "priority": "medium",
                    },
                ]
            )

        return actions

    def _determine_execution_order(self, actions: List[Dict]) -> List[str]:
        """Determine optimal execution order for actions"""
        # Prioritize containment actions before remediation
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        sorted_actions = sorted(
            actions, key=lambda a: priority_order.get(a.get("priority", "medium"), 99)
        )

        return [action["action"] for action in sorted_actions]

    def execute_plan(self, plan: ResponsePlan) -> ResponseExecution:
        """Execute a response plan"""
        import uuid

        start_time = time.time()

        results = []
        all_success = True

        plan.status = "executing"

        for action in plan.execution_order:
            result = self._execute_action(action, plan)
            results.append(result)

            if not result.success:
                all_success = False
                # Stop on critical failures
                if any(
                    a.get("priority") == "critical"
                    for a in plan.actions
                    if a["action"] == action
                ):
                    break

        execution_time = time.time() - start_time

        execution = ResponseExecution(
            execution_id=str(uuid.uuid4()),
            plan_id=plan.plan_id,
            results=results,
            success=all_success,
            execution_time=execution_time,
            timestamp=time.time(),
        )

        plan.status = "completed" if all_success else "partial"
        self.executions.append(execution)

        return execution

    def _execute_action(self, action: str, plan: ResponsePlan) -> Any:
        """Execute a single action"""
        # Find action details
        action_details = next((a for a in plan.actions if a["action"] == action), {})

        if not action_details:
            return {"success": False, "error": "Action not found in plan"}

        action_type = action_details.get("type")

        try:
            if action_type == "containment":
                return self._execute_containment(action, action_details)
            elif action_type == "remediation":
                return self._execute_remediation(action, action_details)
            else:
                return {
                    "success": False,
                    "error": f"Unknown action type: {action_type}",
                }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _execute_containment(self, action: str, details: Dict) -> Any:
        """Execute a containment action"""
        if action == "isolate_host":
            # Would get target from threat context
            return self.containment.isolate_host("target_host")
        elif action == "block_ip":
            return self.containment.block_ip("target_ip")
        elif action == "terminate_process":
            return self.containment.terminate_process("target_host", 1234)
        elif action == "disable_account":
            return self.containment.disable_account("target_user")
        elif action == "revoke_sessions":
            return self.containment.revoke_sessions("target_user")
        else:
            return {"success": False, "error": f"Unknown containment action: {action}"}

    def _execute_remediation(self, action: str, details: Dict) -> Any:
        """Execute a remediation action"""
        if action == "apply_patch":
            return self.remediation.apply_patch("target_host", "patch_id")
        elif action == "update_firewall_rules":
            return self.remediation.update_firewall_rules("target_host", [])
        elif action == "harden_configuration":
            return self.remediation.harden_configuration("target_host", "ssh")
        elif action == "rotate_credentials":
            return self.remediation.rotate_credentials("service_name")
        elif action == "restore_from_backup":
            return self.remediation.restore_from_backup("target_host", "backup_id")
        else:
            return {"success": False, "error": f"Unknown remediation action: {action}"}

    def get_plan(self, plan_id: str) -> Optional[ResponsePlan]:
        """Get a specific response plan"""
        for plan in self.plans:
            if plan.plan_id == plan_id:
                return plan
        return None

    def get_execution(self, execution_id: str) -> Optional[ResponseExecution]:
        """Get a specific execution"""
        for execution in self.executions:
            if execution.execution_id == execution_id:
                return execution
        return None

    def list_plans(self) -> List[ResponsePlan]:
        """List all response plans"""
        return self.plans

    def list_executions(self) -> List[ResponseExecution]:
        """List all executions"""
        return self.executions
