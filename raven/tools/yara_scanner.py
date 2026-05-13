"""Backward-compat shim — re-exports YaraScanner from the new adapter module."""
from raven.tools.yara_scan import YaraScanner

__all__ = ["YaraScanner"]
