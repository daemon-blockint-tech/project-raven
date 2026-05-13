"""Backward-compat shim — re-exports JadxAdapter under the legacy name."""
from raven.tools.jadx import JadxAdapter as JadxAnalyzer

__all__ = ["JadxAnalyzer"]
