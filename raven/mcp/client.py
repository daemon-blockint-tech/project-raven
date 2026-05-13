"""MCP (Model Context Protocol) integration for external RE tools"""

import subprocess
import json
from typing import Dict, Any, List

class MCPManager:
    """Manages MCP server connections like GhidraMCP and radare2-mcp"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.servers = {
            "ghidra": config.get("ghidra_mcp_cmd", ["node", "ghidra-mcp/build/index.js"]),
            "radare2": config.get("radare2_mcp_cmd", ["r2mcp"])
        }
        self.active_processes = {}
        
    def start_server(self, name: str) -> bool:
        if name not in self.servers:
            return False
            
        cmd = self.servers[name]
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            self.active_processes[name] = proc
            return True
        except Exception as e:
            return False

    def call_tool(self, server_name: str, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Send JSON-RPC request to MCP server (simplified sync wrapper)"""
        if server_name not in self.active_processes:
            if not self.start_server(server_name):
                return {"error": f"Failed to start MCP server {server_name}"}
                
        proc = self.active_processes[server_name]
        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "callTool",
            "params": {
                "name": tool_name,
                "arguments": arguments
            }
        }
        
        try:
            proc.stdin.write(json.dumps(req) + "\n")
            proc.stdin.flush()
            
            # Very naive synchronous read line (real MCP clients use async readers)
            response = proc.stdout.readline()
            if response:
                return json.loads(response)
            return {"error": "Empty response"}
        except Exception as e:
            return {"error": str(e)}

    def stop_all(self):
        for name, proc in self.active_processes.items():
            proc.terminate()
        self.active_processes.clear()

    def __del__(self):
        self.stop_all()
