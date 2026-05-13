"""Red-team subsystem — defensive jailbreak detection + offensive godmode (gated).

Defensive (always on):
  * ``ParseltongueNormaliser`` — decode 33 obfuscation techniques
  * ``JailbreakDetector``       — L1B3RT4S / G0DM0D3 pattern detection on inbound
  * ``ProviderHardnessTest``    — score active provider's jailbreak resistance

Offensive (off by default, audit-logged, sandbox-scoped):
  * ``OffensiveGodmode`` — auto-jailbreak the active provider for red-team
    exercises. Refuses to run outside an authorized sandbox session.
"""

from raven.redteam.normalizer import ParseltongueNormaliser, NormalisationResult
from raven.redteam.detector import JailbreakDetector, JailbreakDetection
from raven.redteam.hardness_test import ProviderHardnessTest, HardnessReport
from raven.redteam.offensive import OffensiveGodmode, OffensiveResult

__all__ = [
    "ParseltongueNormaliser",
    "NormalisationResult",
    "JailbreakDetector",
    "JailbreakDetection",
    "ProviderHardnessTest",
    "HardnessReport",
    "OffensiveGodmode",
    "OffensiveResult",
]
