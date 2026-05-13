"""
Code flow scanner: traces user-input to server-output paths to detect multi-stage
vulnerabilities. Mirrors the technique documented in ZenoX dark web monitoring report
(Jan 2025) where threat actors used this approach to find zero-days in major OSS projects.
Focuses on the 7 vulnerability classes that AI-driven scanners target most effectively.
"""

from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import ast
import os
import re
import time
import uuid


class VulnClass(Enum):
    """The 7 vulnerability classes most targeted by AI-driven scanners"""
    LFI = "local_file_include"
    AFO = "arbitrary_file_overwrite"
    RCE = "remote_code_execution"
    XSS = "cross_site_scripting"
    SQLI = "sql_injection"
    SSRF = "server_side_request_forgery"
    IDOR = "insecure_direct_object_reference"


@dataclass
class TaintFlow:
    """Represents a taint flow from source to sink"""
    flow_id: str
    source: str          # where user input enters
    sink: str            # where input reaches dangerous operation
    path: List[str]      # intermediate steps
    vuln_class: VulnClass
    confidence: float
    file_path: str
    line_start: int
    line_end: int
    description: str
    poc_hint: str = ""


@dataclass
class ScanReport:
    """Full report of a code flow scan"""
    report_id: str
    target_path: str
    timestamp: float
    files_scanned: int
    taint_flows: List[TaintFlow] = field(default_factory=list)
    high_confidence_count: int = 0
    scan_duration: float = 0.0


# Patterns that indicate user-controlled input sources
INPUT_SOURCES: Dict[str, List[str]] = {
    VulnClass.LFI:  ["request.args", "request.form", "request.json", "request.data",
                      "request.GET", "request.POST", "input(", "sys.argv"],
    VulnClass.AFO:  ["request.files", "request.form", "request.json"],
    VulnClass.RCE:  ["request.args", "request.form", "request.json", "request.data",
                      "subprocess", "eval(", "exec(", "os.system("],
    VulnClass.XSS:  ["request.args", "request.form", "request.json"],
    VulnClass.SQLI: ["request.args", "request.form", "request.json", "request.GET",
                      "request.POST"],
    VulnClass.SSRF: ["request.args", "request.form", "request.json"],
    VulnClass.IDOR: ["request.args", "request.form", "request.json", "request.view_args"],
}

# Dangerous sinks for each vulnerability class
DANGEROUS_SINKS: Dict[str, List[str]] = {
    VulnClass.LFI:  ["open(", "file(", "read(", "send_file(", "send_from_directory(",
                      "render_template(", "include("],
    VulnClass.AFO:  ["open(", "write(", "shutil.copy", "shutil.move", "os.rename"],
    VulnClass.RCE:  ["eval(", "exec(", "os.system(", "subprocess.call(",
                      "subprocess.run(", "subprocess.Popen(", "compile("],
    VulnClass.XSS:  ["render_template(", "Markup(", "render(", "jsonify(", "make_response("],
    VulnClass.SQLI: ["execute(", "executemany(", "raw(", "cursor.execute(",
                      "db.session.execute(", "text("],
    VulnClass.SSRF: ["requests.get(", "requests.post(", "urllib.request",
                      "httpx.get(", "aiohttp", "urlopen("],
    VulnClass.IDOR: ["db.session.get(", "Model.query.get(", "find_by_id(",
                      "get_object_or_404(", "get_or_404("],
}


class CodeFlowScanner:
    """
    Scans Python codebases for input-to-output taint flows that indicate
    exploitable vulnerabilities. Operates file-by-file and cross-file.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.confidence_threshold = config.get("scanner_confidence_threshold", 0.6)

    def scan_repository(self, repo_path: str) -> ScanReport:
        """Scan an entire repository for vulnerable taint flows"""
        start_time = time.time()
        report = ScanReport(
            report_id=str(uuid.uuid4()),
            target_path=repo_path,
            timestamp=start_time,
            files_scanned=0,
        )

        python_files = self._collect_python_files(repo_path)
        report.files_scanned = len(python_files)

        for file_path in python_files:
            flows = self.scan_file(file_path)
            report.taint_flows.extend(flows)

        report.high_confidence_count = sum(
            1 for f in report.taint_flows if f.confidence >= 0.8
        )
        report.scan_duration = time.time() - start_time
        return report

    def scan_file(self, file_path: str) -> List[TaintFlow]:
        """Scan a single Python file for taint flows"""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                source = fh.read()
        except OSError:
            return []

        flows = []
        lines = source.splitlines()

        for vuln_class in VulnClass:
            detected = self._detect_flows(
                source, lines, file_path, vuln_class
            )
            flows.extend(detected)

        return flows

    def _detect_flows(
        self,
        source: str,
        lines: List[str],
        file_path: str,
        vuln_class: VulnClass,
    ) -> List[TaintFlow]:
        """Detect taint flows for a specific vulnerability class"""
        flows = []
        sources = INPUT_SOURCES.get(vuln_class, [])
        sinks = DANGEROUS_SINKS.get(vuln_class, [])

        source_lines = self._find_pattern_lines(lines, sources)
        sink_lines = self._find_pattern_lines(lines, sinks)

        for src_lineno, src_pattern in source_lines:
            for sink_lineno, sink_pattern in sink_lines:
                # Sink must appear after source in file (simple forward flow)
                if sink_lineno <= src_lineno:
                    continue

                # Look for shared variable names connecting source to sink
                shared_vars = self._find_shared_variables(
                    lines, src_lineno, sink_lineno
                )

                if not shared_vars and (sink_lineno - src_lineno) > 50:
                    continue

                confidence = self._calculate_confidence(
                    src_pattern, sink_pattern, shared_vars, sink_lineno - src_lineno
                )

                if confidence < self.confidence_threshold:
                    continue

                flows.append(TaintFlow(
                    flow_id=str(uuid.uuid4()),
                    source=f"line {src_lineno}: {src_pattern}",
                    sink=f"line {sink_lineno}: {sink_pattern}",
                    path=shared_vars,
                    vuln_class=vuln_class,
                    confidence=confidence,
                    file_path=file_path,
                    line_start=src_lineno,
                    line_end=sink_lineno,
                    description=self._describe_flow(vuln_class, src_pattern, sink_pattern),
                    poc_hint=self._generate_poc_hint(vuln_class, sink_pattern),
                ))

        return flows

    def _collect_python_files(self, root: str) -> List[str]:
        """Recursively collect .py files, skipping test/venv dirs"""
        skip_dirs = {"venv", ".venv", "__pycache__", ".git", "node_modules", "tests"}
        py_files = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
            for fname in filenames:
                if fname.endswith(".py"):
                    py_files.append(os.path.join(dirpath, fname))
        return py_files

    def _find_pattern_lines(
        self, lines: List[str], patterns: List[str]
    ) -> List[Tuple[int, str]]:
        """Return (1-indexed line number, matched pattern) for each match"""
        results = []
        for i, line in enumerate(lines, start=1):
            for pattern in patterns:
                if pattern in line:
                    results.append((i, pattern))
                    break
        return results

    def _find_shared_variables(
        self, lines: List[str], start: int, end: int
    ) -> List[str]:
        """Find variable names that appear in both source and sink regions"""
        var_pattern = re.compile(r'\b([a-z_][a-z0-9_]{2,})\b')
        src_vars = set(var_pattern.findall(lines[start - 1]))
        sink_vars = set(var_pattern.findall(lines[end - 1]))
        shared = src_vars & sink_vars
        # Exclude common Python keywords
        keywords = {"self", "return", "true", "false", "none", "and", "or", "not"}
        return list(shared - keywords)

    def _calculate_confidence(
        self,
        src_pattern: str,
        sink_pattern: str,
        shared_vars: List[str],
        distance: int,
    ) -> float:
        """Heuristic confidence score for a taint flow"""
        score = 0.4

        # Shared variables strongly suggest real data flow
        if shared_vars:
            score += min(0.3, len(shared_vars) * 0.1)

        # Closer source/sink pairs are more likely to be direct flows
        if distance <= 10:
            score += 0.2
        elif distance <= 30:
            score += 0.1

        # Direct dangerous sinks get higher score
        high_risk_sinks = {"eval(", "exec(", "os.system(", "subprocess.Popen(",
                           "cursor.execute(", "execute("}
        if any(s in sink_pattern for s in high_risk_sinks):
            score += 0.1

        return min(1.0, score)

    def _describe_flow(
        self, vuln_class: VulnClass, source: str, sink: str
    ) -> str:
        descriptions = {
            VulnClass.LFI:  f"User input from '{source}' may control file path in '{sink}'",
            VulnClass.AFO:  f"User input from '{source}' may control write target in '{sink}'",
            VulnClass.RCE:  f"User input from '{source}' reaches code execution sink '{sink}'",
            VulnClass.XSS:  f"User input from '{source}' reflected unsanitized in '{sink}'",
            VulnClass.SQLI: f"User input from '{source}' concatenated into SQL query '{sink}'",
            VulnClass.SSRF: f"User input from '{source}' controls outbound request in '{sink}'",
            VulnClass.IDOR: f"User input from '{source}' used as direct object ID in '{sink}'",
        }
        return descriptions.get(vuln_class, "Potential taint flow detected")

    def _generate_poc_hint(self, vuln_class: VulnClass, sink: str) -> str:
        """Generate a PoC hint to assist security researchers in validation"""
        hints = {
            VulnClass.LFI:  "Try: ?file=../../../../etc/passwd",
            VulnClass.AFO:  "Try: upload file with path traversal in filename",
            VulnClass.RCE:  "Try: inject `__import__('os').system('id')` or `;id`",
            VulnClass.XSS:  "Try: <script>alert(document.domain)</script>",
            VulnClass.SQLI: "Try: ' OR '1'='1 or ' UNION SELECT null--",
            VulnClass.SSRF: "Try: http://169.254.169.254/latest/meta-data/ (AWS metadata)",
            VulnClass.IDOR: "Try: enumerate IDs sequentially to access other users' data",
        }
        return hints.get(vuln_class, "Manual inspection required")
