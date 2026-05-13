"""CVE recognition and matching for instant vulnerability identification"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import time
import requests


@dataclass
class CVE:
    """CVE vulnerability information"""

    cve_id: str
    description: str
    severity: str
    cvss_score: float
    affected_components: List[str]
    patch_available: bool
    timestamp: float


class CVEMatcher:
    """Recognize and match CVEs for instant vulnerability identification"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.cve_database: Dict[str, CVE] = {}
        self._load_common_cves()

    def _load_common_cves(self):
        """Load common CVEs into memory"""
        # In production, this would query NVD API or local CVE database
        # For now, load some well-known CVEs
        common_cves = [
            {
                "cve_id": "CVE-2017-5638",
                "description": "Apache Struts2 remote code execution",
                "severity": "critical",
                "cvss_score": 10.0,
                "affected_components": ["struts2-core"],
                "patch_available": True,
            },
            {
                "cve_id": "CVE-2021-44228",
                "description": "Log4Shell remote code execution",
                "severity": "critical",
                "cvss_score": 10.0,
                "affected_components": ["log4j-core"],
                "patch_available": True,
            },
            {
                "cve_id": "CVE-2014-0160",
                "description": "Heartbleed OpenSSL vulnerability",
                "severity": "high",
                "cvss_score": 7.5,
                "affected_components": ["openssl"],
                "patch_available": True,
            },
            {
                "cve_id": "CVE-2017-0144",
                "description": "SMB vulnerability (EternalBlue)",
                "severity": "critical",
                "cvss_score": 9.3,
                "affected_components": ["smb"],
                "patch_available": True,
            },
        ]

        for cve_data in common_cves:
            cve = CVE(
                cve_id=cve_data["cve_id"],
                description=cve_data["description"],
                severity=cve_data["severity"],
                cvss_score=cve_data["cvss_score"],
                affected_components=cve_data["affected_components"],
                patch_available=cve_data["patch_available"],
                timestamp=time.time(),
            )
            self.cve_database[cve.cve_id] = cve

    def recognize_cve(self, code: str, version_info: Dict[str, str]) -> Optional[CVE]:
        """Recognize if code contains a known CVE vulnerability"""
        code_lower = code.lower()

        for cve_id, cve in self.cve_database.items():
            # Check if affected components are present
            for component in cve.affected_components:
                if component in code_lower:
                    # Additional check for version matching if version info provided
                    if self._is_version_affected(cve_id, version_info):
                        return cve

        return None

    def _is_version_affected(self, cve_id: str, version_info: Dict) -> bool:
        if not version_info:
            return True
        cve = self.cve_database.get(cve_id)
        if cve is None:
            return True
        component_names = [c.lower() for c in cve.affected_components]
        return any(
            comp in " ".join(version_info.keys()).lower()
            or comp in " ".join(str(v) for v in version_info.values()).lower()
            for comp in component_names
        )

    def search_cve_by_component(self, component: str) -> List[CVE]:
        """Search for CVEs affecting a specific component"""
        component_lower = component.lower()

        matching_cves = []
        for cve in self.cve_database.values():
            if any(component_lower in comp.lower() for comp in cve.affected_components):
                matching_cves.append(cve)

        return matching_cves

    def query_nvd(self, search_query: str) -> List[Dict[str, Any]]:
        """Query NVD database for CVEs (requires internet)"""
        try:
            # NVD API endpoint
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {"keywordSearch": search_query}

            response = requests.get(url, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json()
                return data.get("vulnerabilities", [])

            return []

        except Exception as e:
            print(f"NVD query failed: {e}")
            return []

    def get_cve_details(self, cve_id: str) -> Optional[CVE]:
        """Get detailed information about a specific CVE"""
        # Check local database first
        if cve_id in self.cve_database:
            return self.cve_database[cve_id]

        # Query NVD if not in local database
        cves = self.query_nvd(cve_id)

        if cves:
            cve_data = cves[0]
            metrics = cve_data.get("metrics", {})
            cvss_list = (
                metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
            )
            cvss_entry = cvss_list[0] if cvss_list else {}
            cvss_data = cvss_entry.get("cvssData", {})
            base_score = float(cvss_data.get("baseScore", 5.0))

            cve = CVE(
                cve_id=cve_id,
                description=cve_data.get("descriptions", [{}])[0].get("value", ""),
                severity=self._map_cvss_to_severity(base_score),
                cvss_score=base_score,
                affected_components=[],
                patch_available=True,
                timestamp=time.time(),
            )

            return cve

        return None

    def _map_cvss_to_severity(self, cvss_score: float) -> str:
        """Map CVSS score to severity level"""
        if cvss_score >= 9.0:
            return "critical"
        elif cvss_score >= 7.0:
            return "high"
        elif cvss_score >= 4.0:
            return "medium"
        else:
            return "low"
