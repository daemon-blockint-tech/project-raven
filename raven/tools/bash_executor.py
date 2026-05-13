"""Bash command executor for local and remote script execution"""

from typing import List, Dict, Any, Optional
import subprocess
import time
from dataclasses import dataclass
import shlex


@dataclass
class BashResult:
    """Result of bash command execution"""
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    execution_time: float
    command: str


class BashExecutor:
    """Execute bash commands locally or remotely"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.timeout = config.get("bash_timeout", 300)
        
    def execute(self, command: str, timeout: Optional[int] = None,
                cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None) -> BashResult:
        """Execute a bash command"""
        timeout = timeout or self.timeout
        start_time = time.time()
        
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=env
            )
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                exit_code = process.returncode
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                exit_code = -1
                stderr = f"Command timed out after {timeout}s"
            
            execution_time = time.time() - start_time
            
            return BashResult(
                success=exit_code == 0,
                stdout=stdout.decode('utf-8', errors='ignore'),
                stderr=stderr.decode('utf-8', errors='ignore'),
                exit_code=exit_code,
                execution_time=execution_time,
                command=command
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            return BashResult(
                success=False,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                execution_time=execution_time,
                command=command
            )
    
    def execute_script(self, script_path: str, args: Optional[List[str]] = None,
                     timeout: Optional[int] = None) -> BashResult:
        """Execute a bash script"""
        command = f"bash {script_path}"
        if args:
            command += " " + " ".join(shlex.quote(arg) for arg in args)
        
        return self.execute(command, timeout=timeout)
    
    def execute_commands(self, commands: List[str]) -> List[BashResult]:
        """Execute multiple commands sequentially"""
        results = []
        for command in commands:
            result = self.execute(command)
            results.append(result)
            
            # Stop if a command fails
            if not result.success:
                break
        
        return results
    
    def execute_parallel(self, commands: List[str]) -> List[BashResult]:
        """Execute commands in parallel"""
        import concurrent.futures
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(self.execute, cmd) for cmd in commands]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        return results
    
    def safe_execute(self, command: str) -> BashResult:
        """Execute command with additional safety checks"""
        # Basic command validation
        dangerous_patterns = [
            'rm -rf /',
            'mkfs',
            'dd if=/dev/zero',
            '> /dev/sda',
            'chmod 777 /'
        ]
        
        for pattern in dangerous_patterns:
            if pattern in command:
                return BashResult(
                    success=False,
                    stdout="",
                    stderr=f"Command blocked: contains dangerous pattern '{pattern}'",
                    exit_code=-1,
                    execution_time=0,
                    command=command
                )
        
        return self.execute(command)
