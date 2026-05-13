"""NMAP integration for network scanning and discovery"""

from typing import List, Dict, Any, Optional
import nmap
from dataclasses import dataclass
import time
import json


@dataclass
class NmapScanResult:
    """Result of NMAP scan"""
    success: bool
    target: str
    scan_type: str
    results: Dict[str, Any]
    execution_time: float
    timestamp: float


class NmapScanner:
    """NMAP scanner wrapper for network discovery"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.timeout = config.get("nmap_timeout", 300)
        self.nm = nmap.PortScanner()
        
    def scan_host(self, host: str, ports: str = "1-1024",
                 arguments: str = "-sV -sC") -> NmapScanResult:
        """Scan a single host"""
        start_time = time.time()
        
        try:
            result = self.nm.scan(host, ports, arguments=arguments, timeout=self.timeout)
            execution_time = time.time() - start_time
            
            return NmapScanResult(
                success=True,
                target=host,
                scan_type="host_scan",
                results=result,
                execution_time=execution_time,
                timestamp=time.time()
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            return NmapScanResult(
                success=False,
                target=host,
                scan_type="host_scan",
                results={"error": str(e)},
                execution_time=execution_time,
                timestamp=time.time()
            )
    
    def scan_network(self, network: str, ports: str = "1-1024",
                    arguments: str = "-sV") -> NmapScanResult:
        """Scan a network range"""
        start_time = time.time()
        
        try:
            result = self.nm.scan(network, ports, arguments=arguments, timeout=self.timeout)
            execution_time = time.time() - start_time
            
            return NmapScanResult(
                success=True,
                target=network,
                scan_type="network_scan",
                results=result,
                execution_time=execution_time,
                timestamp=time.time()
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            return NmapScanResult(
                success=False,
                target=network,
                scan_type="network_scan",
                results={"error": str(e)},
                execution_time=execution_time,
                timestamp=time.time()
            )
    
    def scan_ports(self, host: str, ports: List[int],
                  arguments: str = "-sV") -> NmapScanResult:
        """Scan specific ports on a host"""
        ports_str = ",".join(map(str, ports))
        return self.scan_host(host, ports_str, arguments)
    
    def get_open_ports(self, host: str) -> List[Dict[str, Any]]:
        """Get list of open ports for a host"""
        if host not in self.nm.all_hosts():
            return []
        
        open_ports = []
        for port in self.nm[host]['tcp']:
            if self.nm[host]['tcp'][port]['state'] == 'open':
                port_info = {
                    'port': port,
                    'state': self.nm[host]['tcp'][port]['state'],
                    'service': self.nm[host]['tcp'][port].get('name', 'unknown'),
                    'product': self.nm[host]['tcp'][port].get('product', ''),
                    'version': self.nm[host]['tcp'][port].get('version', '')
                }
                open_ports.append(port_info)
        
        return open_ports
    
    def get_host_info(self, host: str) -> Dict[str, Any]:
        """Get detailed information about a host"""
        if host not in self.nm.all_hosts():
            return {}
        
        host_info = {
            'host': host,
            'state': self.nm[host].state(),
            'hostname': self.nm[host].hostname(),
            'ports': self.get_open_ports(host),
            'os': self.nm[host].get('osmatch', [])
        }
        
        return host_info
    
    def vulnerability_scan(self, host: str, ports: str = "1-1024") -> NmapScanResult:
        """Perform vulnerability scan using NSE scripts"""
        arguments = "--script vuln -sV"
        return self.scan_host(host, ports, arguments)
    
    def stealth_scan(self, host: str, ports: str = "1-1024") -> NmapScanResult:
        """Perform stealth scan"""
        arguments = "-sS -sV -T2"
        return self.scan_host(host, ports, arguments)
    
    def export_results(self, result: NmapScanResult, format: str = "json") -> str:
        """Export scan results to specified format"""
        if format == "json":
            return json.dumps(result.results, indent=2)
        elif format == "xml":
            return self.nm.get_nmap_last_output() or ""
        else:
            return str(result.results)
