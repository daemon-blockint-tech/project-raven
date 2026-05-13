"""Empire C2 REST API client (Empire 5.x, BSD-3-Clause)

Communicates with an Empire server via its REST API using only `requests`,
which is already a project dependency.  No new pip packages required.

SSL verification is controlled via config key `empire_ssl_verify` (default True).
Operators using self-signed certs must explicitly set it to False.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import requests
import time


@dataclass
class EmpireResult:
    """Result of an Empire API operation"""

    success: bool
    operation: str
    agent_name: str
    output: str
    execution_time: float
    timestamp: float


class EmpireClient:
    """Thin REST client for Empire 5.x post-exploitation framework.

    All methods return an EmpireResult and never raise — callers receive
    success=False with an error message in `output` on any failure.
    """

    def __init__(self, config: Dict[str, Any]):
        self.base_url = config.get("empire_url", "http://localhost:1337").rstrip("/")
        self.ssl_verify: bool = config.get("empire_ssl_verify", True)
        self.token: Optional[str] = None
        self._session = requests.Session()
        self._session.verify = self.ssl_verify

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def authenticate(self, username: str, password: str) -> bool:
        """Obtain a JWT from Empire and store it for subsequent calls."""
        try:
            resp = self._session.post(
                f"{self.base_url}/api/v2/token",
                json={"username": username, "password": password},
                timeout=10,
            )
            if resp.status_code == 200:
                self.token = resp.json().get("token")
                self._session.headers["Authorization"] = f"Bearer {self.token}"
                return True
            return False
        except Exception:
            return False

    def is_authenticated(self) -> bool:
        return self.token is not None

    # ------------------------------------------------------------------
    # Agent queries
    # ------------------------------------------------------------------

    def list_agents(self) -> List[Dict[str, Any]]:
        """Return list of active agents, empty list on any error."""
        try:
            resp = self._session.get(f"{self.base_url}/api/v2/agents", timeout=10)
            if resp.status_code == 200:
                return resp.json().get("records", [])
        except Exception:
            pass
        return []

    # ------------------------------------------------------------------
    # Task execution
    # ------------------------------------------------------------------

    def execute_module(
        self,
        agent_name: str,
        module: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> EmpireResult:
        """Queue a module task on an agent."""
        start = time.time()
        try:
            resp = self._session.post(
                f"{self.base_url}/api/v2/agents/{agent_name}/tasks/module",
                json={"module_id": module, "options": options or {}},
                timeout=30,
            )
            success = resp.status_code == 201
            output = resp.json().get("output", "") if success else resp.text
            return EmpireResult(
                success=success,
                operation="execute_module",
                agent_name=agent_name,
                output=output,
                execution_time=round(time.time() - start, 3),
                timestamp=start,
            )
        except Exception as e:
            return EmpireResult(
                success=False,
                operation="execute_module",
                agent_name=agent_name,
                output=str(e),
                execution_time=round(time.time() - start, 3),
                timestamp=start,
            )

    def run_shell(self, agent_name: str, command: str) -> EmpireResult:
        """Queue a shell command task on an agent."""
        start = time.time()
        try:
            resp = self._session.post(
                f"{self.base_url}/api/v2/agents/{agent_name}/tasks/shell",
                json={"command": command},
                timeout=30,
            )
            success = resp.status_code == 201
            output = resp.json().get("output", "") if success else resp.text
            return EmpireResult(
                success=success,
                operation="shell",
                agent_name=agent_name,
                output=output,
                execution_time=round(time.time() - start, 3),
                timestamp=start,
            )
        except Exception as e:
            return EmpireResult(
                success=False,
                operation="shell",
                agent_name=agent_name,
                output=str(e),
                execution_time=round(time.time() - start, 3),
                timestamp=start,
            )

    def get_task_result(self, agent_name: str, task_id: int) -> EmpireResult:
        """Poll a previously queued task for its output."""
        start = time.time()
        try:
            resp = self._session.get(
                f"{self.base_url}/api/v2/agents/{agent_name}/tasks/{task_id}",
                timeout=10,
            )
            success = resp.status_code == 200
            data = resp.json() if success else {}
            output = data.get("output", "") or resp.text
            return EmpireResult(
                success=success,
                operation="get_task_result",
                agent_name=agent_name,
                output=output,
                execution_time=round(time.time() - start, 3),
                timestamp=start,
            )
        except Exception as e:
            return EmpireResult(
                success=False,
                operation="get_task_result",
                agent_name=agent_name,
                output=str(e),
                execution_time=round(time.time() - start, 3),
                timestamp=start,
            )
