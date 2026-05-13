"""SSH manager for secure remote command execution"""

from typing import List, Dict, Any, Optional
import paramiko
from dataclasses import dataclass
import time


@dataclass
class SSHResult:
    """Result of SSH command execution"""
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    execution_time: float
    host: str


class SSHManager:
    """Manage SSH connections and command execution"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.timeout = config.get("ssh_timeout", 30)
        self.connections: Dict[str, paramiko.SSHClient] = {}
        
    def connect(self, host: str, username: str, password: Optional[str] = None,
                key_path: Optional[str] = None, port: int = 22) -> bool:
        """Establish SSH connection to a host"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if key_path:
                client.connect(host, port=port, username=username, 
                             key_filename=key_path, timeout=self.timeout)
            else:
                client.connect(host, port=port, username=username,
                             password=password, timeout=self.timeout)
            
            self.connections[host] = client
            return True
            
        except Exception as e:
            print(f"SSH connection failed to {host}: {e}")
            return False
    
    def execute_command(self, host: str, command: str) -> SSHResult:
        """Execute a command on a remote host via SSH"""
        if host not in self.connections:
            raise ValueError(f"No connection to host {host}")
        
        client = self.connections[host]
        start_time = time.time()
        
        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=self.timeout)
            
            stdout_str = stdout.read().decode('utf-8')
            stderr_str = stderr.read().decode('utf-8')
            exit_code = stdout.channel.recv_exit_status()
            execution_time = time.time() - start_time
            
            return SSHResult(
                success=exit_code == 0,
                stdout=stdout_str,
                stderr=stderr_str,
                exit_code=exit_code,
                execution_time=execution_time,
                host=host
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            return SSHResult(
                success=False,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                execution_time=execution_time,
                host=host
            )
    
    def execute_commands(self, host: str, commands: List[str]) -> List[SSHResult]:
        """Execute multiple commands on a host"""
        results = []
        for command in commands:
            result = self.execute_command(host, command)
            results.append(result)
        return results
    
    def disconnect(self, host: str) -> bool:
        """Close SSH connection to a host"""
        if host in self.connections:
            try:
                self.connections[host].close()
                del self.connections[host]
                return True
            except Exception as e:
                print(f"Error disconnecting from {host}: {e}")
                return False
        return False
    
    def disconnect_all(self) -> None:
        """Close all SSH connections"""
        for host in list(self.connections.keys()):
            self.disconnect(host)
    
    def get_connected_hosts(self) -> List[str]:
        """Get list of currently connected hosts"""
        return list(self.connections.keys())
    
    def __del__(self):
        """Cleanup connections on deletion"""
        self.disconnect_all()
