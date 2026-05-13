"""Memory corruption vulnerability detection"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import os
import time
import subprocess


@dataclass
class MemoryVulnerability:
    """Memory corruption vulnerability"""
    vuln_id: str
    vuln_type: str  # buffer_overflow, use_after_free, null_dereference, etc.
    severity: str
    location: str
    crash_info: Dict[str, Any]
    confidence: float
    timestamp: float
    description: str


class MemoryAnalyzer:
    """Detect memory corruption vulnerabilities using address sanitizers"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.address_sanitizer_enabled = config.get("address_sanitizer", True)
        self.valgrind_enabled = config.get("valgrind", False)
        
    def analyze_crash(self, crash_log: str, binary_path: str) -> Optional[MemoryVulnerability]:
        """Analyze a crash to identify memory vulnerability"""
        import uuid
        
        # Parse crash log
        crash_info = self._parse_crash_log(crash_log)
        
        if not crash_info:
            return None
        
        # Classify vulnerability type
        vuln_type = self._classify_memory_vulnerability(crash_info)
        
        if not vuln_type:
            return None
        
        # Determine severity
        severity = self._assess_severity(vuln_type, crash_info)
        
        return MemoryVulnerability(
            vuln_id=str(uuid.uuid4()),
            vuln_type=vuln_type,
            severity=severity,
            location=crash_info.get("location", "unknown"),
            crash_info=crash_info,
            confidence=0.9,
            timestamp=time.time(),
            description=f"Memory corruption detected: {vuln_type}"
        )
    
    def _parse_crash_log(self, crash_log: str) -> Optional[Dict[str, Any]]:
        """Parse crash log for memory corruption indicators"""
        crash_info = {}
        
        # Look for memory corruption patterns
        patterns = {
            "buffer_overflow": ["stack overflow", "buffer overflow", "stack smashing"],
            "use_after_free": ["use after free", "double free", "invalid pointer"],
            "null_dereference": ["null pointer", "segmentation fault", "NULL dereference"],
            "heap_overflow": ["heap overflow", "heap corruption"],
            "race_condition": ["data race", "thread safety"]
        }
        
        crash_lower = crash_log.lower()
        
        for vuln_type, indicators in patterns.items():
            for indicator in indicators:
                if indicator in crash_lower:
                    crash_info["type"] = vuln_type
                    crash_info["indicator"] = indicator
                    break
        
        # Extract stack trace if present
        if "stack trace" in crash_lower or "#0" in crash_log:
            crash_info["has_stack_trace"] = True
        
        # Extract memory address if present
        import re
        addr_match = re.search(r'0x[0-9a-f]+', crash_log)
        if addr_match:
            crash_info["memory_address"] = addr_match.group()
        
        return crash_info if crash_info else None
    
    def _classify_memory_vulnerability(self, crash_info: Dict) -> Optional[str]:
        """Classify the type of memory vulnerability"""
        return crash_info.get("type")
    
    def _assess_severity(self, vuln_type: str, crash_info: Dict) -> str:
        """Assess severity based on vulnerability type"""
        critical_types = ["buffer_overflow", "heap_overflow"]
        high_types = ["use_after_free", "null_dereference"]
        
        if vuln_type in critical_types:
            return "critical"
        elif vuln_type in high_types:
            return "high"
        else:
            return "medium"
    
    @staticmethod
    def _safe_binary_path(binary_path: str) -> str:
        path = os.path.realpath(binary_path)
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Binary not found: {path}")
        if not os.access(path, os.X_OK):
            raise PermissionError(f"Binary not executable: {path}")
        return path

    def run_with_asan(self, binary_path: str, args: List[str]) -> Dict[str, Any]:
        """Run binary with AddressSanitizer to detect memory errors"""
        if not self.address_sanitizer_enabled:
            return {"enabled": False}

        try:
            safe_path = self._safe_binary_path(binary_path)
        except (FileNotFoundError, PermissionError) as e:
            return {"enabled": False, "error": str(e)}

        env = {
            "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=0"
        }

        try:
            result = subprocess.run(
                [safe_path] + args,
                env=env,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return {
                "enabled": True,
                "exit_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "has_errors": "ERROR" in result.stderr or "runtime error" in result.stderr.lower()
            }
            
        except subprocess.TimeoutExpired:
            return {"enabled": True, "timeout": True}
        except Exception as e:
            return {"enabled": True, "error": str(e)}
    
    def run_with_valgrind(self, binary_path: str, args: List[str]) -> Dict[str, Any]:
        """Run binary with Valgrind for memory analysis"""
        if not self.valgrind_enabled:
            return {"enabled": False}

        try:
            safe_path = self._safe_binary_path(binary_path)
        except (FileNotFoundError, PermissionError) as e:
            return {"enabled": False, "error": str(e)}

        try:
            result = subprocess.run(
                ["valgrind", "--leak-check=full", safe_path] + args,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            return {
                "enabled": True,
                "exit_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "has_leaks": "definitely lost" in result.stderr or "indirectly lost" in result.stderr
            }
            
        except subprocess.TimeoutExpired:
            return {"enabled": True, "timeout": True}
        except Exception as e:
            return {"enabled": True, "error": str(e)}
    
    def validate_vulnerability(self, vuln: MemoryVulnerability, binary_path: str) -> bool:
        """Validate by running the binary with ASAN and checking for the expected error type."""
        result = self.run_with_asan(binary_path, [])
        if not result.get("enabled"):
            return False
        if result.get("timeout") or result.get("error"):
            return False
        stderr = result.get("stderr", "")
        vuln_indicators = {
            "buffer_overflow": ["stack-buffer-overflow", "global-buffer-overflow"],
            "heap_overflow":   ["heap-buffer-overflow"],
            "use_after_free":  ["heap-use-after-free", "double-free"],
            "null_dereference": ["null-pointer", "SEGV on unknown address"],
            "race_condition":   ["data race"],
        }
        for indicator in vuln_indicators.get(vuln.vuln_type, []):
            if indicator.lower() in stderr.lower():
                return True
        return result.get("has_errors", False)
