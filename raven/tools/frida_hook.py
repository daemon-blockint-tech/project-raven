"""Backward-compat shim — re-exports FridaAdapter under the legacy name."""
from raven.tools.frida import FridaAdapter as FridaHook

__all__ = ["FridaHook"]
