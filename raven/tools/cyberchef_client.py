"""Backward-compat shim — re-exports CyberchefAdapter under the legacy name."""
from raven.tools.cyberchef import CyberchefAdapter as CyberChefClient

__all__ = ["CyberChefClient"]
