"""Jadx — Android DEX/APK/JAR to Java decompiler.

Used by Raven's hunters when the target is an Android sample (CyberGym
covers some via OSS-Fuzz, plus general malware-analysis flows).
"""

from __future__ import annotations

import os
import tempfile
from typing import Any, Dict, List, Optional

from raven.tools.adapter_base import ToolAdapter, ToolResult, is_safe_arg


class JadxAdapter(ToolAdapter):
    binary = "jadx"
    install_hint = (
        "git clone https://gitlab.com/kalilinux/packages/jadx.git && cd jadx && "
        "./gradlew dist  (or apt install jadx)"
    )

    def decompile(
        self,
        target: str,
        out_dir: Optional[str] = None,
        deobfuscate: bool = True,
        no_src: bool = False,
        no_res: bool = False,
    ) -> ToolResult:
        """Decompile ``target`` (.apk / .dex / .jar / .class / .aar) into Java."""
        if not is_safe_arg(target) or not os.path.isfile(target):
            return ToolResult(tool=self.tool_name, success=False, target=target,
                              error="target not found or unsafe")
        out_dir = out_dir or tempfile.mkdtemp(prefix="raven_jadx_")
        if not is_safe_arg(out_dir):
            return ToolResult(tool=self.tool_name, success=False, target=target,
                              error="invalid out_dir")
        args = [self.binary, "-d", out_dir]
        if deobfuscate:
            args.append("--deobf")
        if no_src:
            args.append("--no-src")
        if no_res:
            args.append("--no-res")
        args.append(target)
        result = self._run(args, target=target)
        result.parsed = {"out_dir": out_dir} if result.success else {}
        return result
