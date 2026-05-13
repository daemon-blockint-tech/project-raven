"""Backward-compat shim — re-exports Radare2Adapter under the legacy name."""
from raven.tools.radare2 import Radare2Adapter as RadareClient

__all__ = ["RadareClient"]
