"""
Variant analysis engine.
Implements the three LLM-orthogonal discovery techniques from Anthropic's
Claude Opus 4.6 research (Feb 2026, llm-0days-research):

  1. Git history variant analysis  — find incomplete patches applied in one
     location but missed in related code paths (GhostScript technique).
  2. Precondition-chain analysis   — identify code paths with deep preconditions
     that fuzzers cannot reach (OpenSC technique).
  3. Algorithmic assumption checking — detect false design assumptions about
     mathematical properties (CGIF/LZW technique).

Also incorporates ZeroDayBench grep patterns (arXiv-2603.02297):
  subprocess.*shell=True, pickle.loads, yaml.unsafe_load, eval(), exec().
"""

from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import subprocess
import os
import re
import time
import uuid


class VariantType(Enum):
    INCOMPLETE_PATCH       = "incomplete_patch"
    DEEP_PRECONDITION      = "deep_precondition"
    ALGORITHM_ASSUMPTION   = "algorithm_assumption"
    DANGEROUS_PATTERN      = "dangerous_pattern"


@dataclass
class VariantFinding:
    finding_id: str
    variant_type: VariantType
    file_path: str
    line_number: int
    description: str
    evidence: str
    confidence: float
    related_cve: Optional[str] = None
    git_commit: Optional[str] = None
    reproduction_hint: str = ""


# ------------------------------------------------------------------
# ZeroDayBench grep patterns (patterns that directly locate vulns)
# Derived from Grok/GPT success strategies in ZeroDayBench case studies
# ------------------------------------------------------------------
DANGEROUS_PATTERNS: List[Tuple[str, str, str]] = [
    # (regex, description, reproduction_hint)
    (r"subprocess\.(run|call|Popen|check_output)\s*\(.*shell\s*=\s*True",
     "subprocess call with shell=True — command injection risk",
     "Inject: `'; id #` or `$(id)` via user-controlled input"),

    (r"pickle\.loads?\s*\(",
     "pickle.loads — arbitrary code execution via deserialization",
     "Craft malicious pickle payload: pickle.dumps(os.system('id'))"),

    (r"yaml\.(unsafe_load|load)\s*\((?!.*safe)",
     "yaml.load/unsafe_load — arbitrary Python object instantiation",
     "YAML payload: !!python/object/apply:os.system ['id']"),

    (r"eval\s*\(",
     "eval() — arbitrary code execution",
     "Inject Python expression via user input"),

    (r"exec\s*\(",
     "exec() — arbitrary code execution",
     "Inject Python statements via user input"),

    (r"marshal\.loads?\s*\(",
     "marshal.loads — arbitrary bytecode execution",
     "Craft malicious marshal payload"),

    (r"__import__\s*\(",
     "Dynamic __import__ — may allow module injection",
     "Inject module name to load unexpected code"),

    (r"os\.system\s*\(",
     "os.system — command injection if input is unsanitized",
     "Inject shell metacharacters: ; && ||"),

    (r"open\s*\(.*['\"]w['\"]",
     "File write with potentially user-controlled path",
     "Path traversal: ../../../../etc/cron.d/backdoor"),

    (r"strcat\s*\(",
     "strcat() without bounds check — buffer overflow risk (C code)",
     "Supply PATH_MAX+ string to overflow fixed buffer"),

    (r"strcpy\s*\(",
     "strcpy() — classic buffer overflow",
     "Supply input longer than destination buffer"),

    (r"sprintf\s*\(",
     "sprintf without snprintf — potential buffer overflow",
     "Supply format string longer than destination buffer"),
]

# Algorithm design assumption checks (CGIF/LZW pattern)
ALGORITHM_ASSUMPTIONS: List[Tuple[str, str, str]] = [
    (r"compressed.*<.*input|output.*<=.*input|buf.*len.*compressed",
     "Code assumes compressed output is always smaller than input",
     "LZW/Deflate can expand incompressible data — overflow possible"),

    (r"len\(.*\)\s*<=\s*len\(.*original",
     "Implicit assumption: output length bounded by input length",
     "Verify algorithm guarantees — some encodings expand data"),

    (r"malloc\s*\(\s*input_len|buf\s*=.*alloc.*input\.size",
     "Buffer allocated based on input size without expansion factor",
     "Encoding/compression/escaping may produce output > input"),
]


# Pre-compiled for performance — avoid recompiling per line
_COMPILED_DANGEROUS = [
    (re.compile(pat, re.IGNORECASE), desc, hint)
    for pat, desc, hint in DANGEROUS_PATTERNS
]
_COMPILED_ASSUMPTIONS = [
    (re.compile(pat, re.IGNORECASE), desc, hint)
    for pat, desc, hint in ALGORITHM_ASSUMPTIONS
]


class VariantAnalyzer:
    """
    Performs variant analysis on Python (and C) codebases using three
    techniques derived from Anthropic's Opus 4.6 vulnerability research.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.confidence_threshold = config.get("variant_confidence_threshold", 0.5)

    def analyze_repository(self, repo_path: str) -> List[VariantFinding]:
        """Run all three analysis techniques on a repository"""
        findings = []
        findings.extend(self._scan_dangerous_patterns(repo_path))
        findings.extend(self._analyze_git_variants(repo_path))
        findings.extend(self._check_algorithm_assumptions(repo_path))
        findings.extend(self._find_deep_preconditions(repo_path))
        return [f for f in findings if f.confidence >= self.confidence_threshold]

    # ------------------------------------------------------------------
    # 1. Dangerous pattern grep (ZeroDayBench technique)
    # ------------------------------------------------------------------

    def _scan_dangerous_patterns(self, repo_path: str) -> List[VariantFinding]:
        findings = []
        py_files = self._collect_files(repo_path, extensions=[".py", ".c", ".cpp", ".h"])

        for file_path in py_files:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                    lines = fh.readlines()
            except OSError:
                continue

            for lineno, line in enumerate(lines, start=1):
                for compiled_pat, description, hint in _COMPILED_DANGEROUS:
                    if compiled_pat.search(line):
                        findings.append(VariantFinding(
                            finding_id=str(uuid.uuid4()),
                            variant_type=VariantType.DANGEROUS_PATTERN,
                            file_path=file_path,
                            line_number=lineno,
                            description=description,
                            evidence=line.strip(),
                            confidence=0.75,
                            reproduction_hint=hint,
                        ))
        return findings

    # ------------------------------------------------------------------
    # 2. Git history variant analysis (GhostScript technique)
    # ------------------------------------------------------------------

    def _analyze_git_variants(self, repo_path: str) -> List[VariantFinding]:
        """
        Scan git commit history for security-relevant fixes, then check
        whether the fix was applied consistently across the codebase.
        Implements Claude's GhostScript discovery methodology.
        """
        findings = []

        if not os.path.exists(os.path.join(repo_path, ".git")):
            return findings

        # Step 1: Find security-relevant commits
        security_commits = self._get_security_commits(repo_path)

        for commit_hash, commit_msg, changed_files in security_commits:
            # Step 2: Extract the fix pattern from the diff
            fix_patterns = self._extract_fix_patterns(repo_path, commit_hash)

            for fix_pattern, context in fix_patterns:
                # Step 3: Search for sibling code that lacks the fix
                missing_locations = self._find_missing_fix_locations(
                    repo_path, fix_pattern, context, changed_files
                )

                for file_path, lineno, evidence in missing_locations:
                    findings.append(VariantFinding(
                        finding_id=str(uuid.uuid4()),
                        variant_type=VariantType.INCOMPLETE_PATCH,
                        file_path=file_path,
                        line_number=lineno,
                        description=(
                            f"Security fix from commit {commit_hash[:8]} "
                            f"({commit_msg[:60]}) not applied here"
                        ),
                        evidence=evidence,
                        confidence=0.70,
                        git_commit=commit_hash,
                        reproduction_hint=(
                            "Trigger the code path that was patched in the "
                            "original commit but not at this location"
                        ),
                    ))

        return findings

    def _get_security_commits(self, repo_path: str) -> List[Tuple[str, str, List[str]]]:
        """Find commits with security-relevant keywords in their messages"""
        security_keywords = [
            "bounds check", "buffer overflow", "sanitize", "validate",
            "fix security", "CVE-", "security fix", "out of bounds",
            "integer overflow", "null check", "bounds checking",
        ]
        results = []
        # Use --grep at git level to avoid pulling 200 commits and filtering in Python
        grep_args = []
        for kw in security_keywords:
            grep_args += ["--grep", kw]
        try:
            log_output = subprocess.check_output(
                ["git", "log", "--oneline", "--no-merges",
                 "--regexp-ignore-case"] + grep_args,
                cwd=repo_path, stderr=subprocess.DEVNULL, timeout=15,
                text=True,
            )
            for line in log_output.splitlines():
                parts = line.split(" ", 1)
                if len(parts) < 2:
                    continue
                commit_hash, commit_msg = parts[0], parts[1]
                changed = self._get_changed_files(repo_path, commit_hash)
                results.append((commit_hash, commit_msg, changed))
        except (subprocess.SubprocessError, OSError):
            pass
        return results

    def _get_changed_files(self, repo_path: str, commit_hash: str) -> List[str]:
        try:
            output = subprocess.check_output(
                ["git", "diff-tree", "--no-commit-id", "-r", "--name-only", commit_hash],
                cwd=repo_path, stderr=subprocess.DEVNULL, timeout=10, text=True,
            )
            return output.strip().splitlines()
        except (subprocess.SubprocessError, OSError):
            return []

    def _extract_fix_patterns(
        self, repo_path: str, commit_hash: str
    ) -> List[Tuple[str, str]]:
        """Extract added lines from a security commit as potential fix patterns"""
        patterns = []
        try:
            diff = subprocess.check_output(
                ["git", "show", "--unified=3", commit_hash],
                cwd=repo_path, stderr=subprocess.DEVNULL, timeout=10, text=True,
            )
            for line in diff.splitlines():
                if line.startswith("+") and not line.startswith("+++"):
                    added = line[1:].strip()
                    # Only consider lines that look like safety checks
                    if re.search(
                        r"(bounds|check|validate|sanitize|assert|if.*len|"
                        r"if.*null|if.*size|snprintf|strncat|strncpy)",
                        added, re.IGNORECASE
                    ):
                        patterns.append((added, commit_hash))
        except (subprocess.SubprocessError, OSError):
            pass
        return patterns

    def _find_missing_fix_locations(
        self,
        repo_path: str,
        fix_pattern: str,
        context: str,
        patched_files: List[str],
    ) -> List[Tuple[str, int, str]]:
        """
        Find functions/locations similar to the patched code that still
        lack the fix. Basic heuristic: look for the same unsafe function
        call that was fixed but in different files.
        """
        results = []
        # Match both C unsafe functions and Python dangerous calls
        unsafe_match = re.search(
            r"\b(strcat|strcpy|sprintf|gets|scanf|memcpy|memmove"
            r"|pickle\.loads?|yaml\.unsafe_load|yaml\.load"
            r"|subprocess\.(run|Popen|call)|os\.system|eval|exec)\s*[\.(]",
            fix_pattern,
        )
        if not unsafe_match:
            return results

        # Escape for safe use in a pattern; strip trailing punctuation
        unsafe_fn = re.escape(unsafe_match.group(1).rstrip("("))
        search_re = re.compile(rf"\b{unsafe_fn}\s*[\.(]") 
        all_files = self._collect_files(repo_path, extensions=[".c", ".cpp", ".h", ".py"])

        for file_path in all_files:
            rel = os.path.relpath(file_path, repo_path)
            if rel in patched_files:
                continue
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                    lines = fh.readlines()
            except OSError:
                continue

            for lineno, line in enumerate(lines, start=1):
                if search_re.search(line):
                    results.append((file_path, lineno, line.strip()))

        return results

    # ------------------------------------------------------------------
    # 3. Algorithm assumption checking (CGIF/LZW technique)
    # ------------------------------------------------------------------

    def _check_algorithm_assumptions(self, repo_path: str) -> List[VariantFinding]:
        findings = []
        files = self._collect_files(repo_path, extensions=[".py", ".c", ".cpp"])

        for file_path in files:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                    lines = fh.readlines()
            except OSError:
                continue

            for lineno, line in enumerate(lines, start=1):
                for compiled_pat, description, hint in _COMPILED_ASSUMPTIONS:
                    if compiled_pat.search(line):
                        findings.append(VariantFinding(
                            finding_id=str(uuid.uuid4()),
                            variant_type=VariantType.ALGORITHM_ASSUMPTION,
                            file_path=file_path,
                            line_number=lineno,
                            description=description,
                            evidence=line.strip(),
                            confidence=0.60,
                            reproduction_hint=hint,
                        ))
        return findings

    # ------------------------------------------------------------------
    # 4. Deep precondition analysis (OpenSC technique)
    # ------------------------------------------------------------------

    def _find_deep_preconditions(self, repo_path: str) -> List[VariantFinding]:
        """
        Find code paths with many conditional checks before reaching a
        dangerous operation — these are the paths fuzzers never reach.
        """
        findings = []
        files = self._collect_files(repo_path, extensions=[".py", ".c", ".cpp"])

        danger_re = re.compile(
            r"\b(strcat|strcpy|sprintf|gets|eval|exec|pickle\.load|"
            r"subprocess\.(run|Popen)|os\.system)\s*\("
        )
        cond_re = re.compile(r"^\s*(if|elif|while|for|switch)\b")

        for file_path in files:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                    lines = fh.readlines()
            except OSError:
                continue

            for lineno, line in enumerate(lines, start=1):
                if not danger_re.search(line):
                    continue
                # Count conditionals in preceding 30 lines.
                # lineno is 1-indexed; lines list is 0-indexed.
                # lines[lineno-1] is the current line, so slice [lineno-31:lineno-1]
                context_start = max(0, lineno - 31)
                precond_count = sum(
                    1 for l in lines[context_start:lineno - 1]
                    if cond_re.match(l)
                )
                if precond_count >= 4:
                    findings.append(VariantFinding(
                        finding_id=str(uuid.uuid4()),
                        variant_type=VariantType.DEEP_PRECONDITION,
                        file_path=file_path,
                        line_number=lineno,
                        description=(
                            f"Dangerous operation behind {precond_count} "
                            "conditionals — fuzzers unlikely to reach this path"
                        ),
                        evidence=line.strip(),
                        confidence=0.55 + min(0.25, precond_count * 0.03),
                        reproduction_hint=(
                            "Manually trace preconditions and craft input that "
                            "satisfies all guards to reach the dangerous operation"
                        ),
                    ))
        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _collect_files(self, root: str, extensions: List[str]) -> List[str]:
        skip_dirs = {"venv", ".venv", "__pycache__", ".git", "node_modules", "tests"}
        result = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
            for fname in filenames:
                if any(fname.endswith(ext) for ext in extensions):
                    result.append(os.path.join(dirpath, fname))
        return result

    def summarize(
        self, findings: List[VariantFinding], base_path: str = ""
    ) -> Dict[str, Any]:
        by_type: Dict[str, int] = {}
        for f in findings:
            by_type[f.variant_type.value] = by_type.get(f.variant_type.value, 0) + 1

        def _rel(path: str) -> str:
            if base_path:
                try:
                    return os.path.relpath(path, base_path)
                except ValueError:
                    pass
            return path

        return {
            "total_findings": len(findings),
            "by_type": by_type,
            "high_confidence": sum(1 for f in findings if f.confidence >= 0.75),
            "findings": [
                {
                    "id": f.finding_id,
                    "type": f.variant_type.value,
                    "file": _rel(f.file_path),
                    "line": f.line_number,
                    "confidence": round(f.confidence, 2),
                    "description": f.description,
                    "evidence": f.evidence,
                    "hint": f.reproduction_hint,
                    "cve": f.related_cve,
                    "commit": f.git_commit,
                }
                for f in sorted(findings, key=lambda x: x.confidence, reverse=True)
            ],
        }
