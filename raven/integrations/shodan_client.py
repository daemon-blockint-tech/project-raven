"""
Shodan integration for Project Raven.
Wraps the shodan-python library (https://github.com/achillean/shodan-python)
for offensive reconnaissance and defensive threat intelligence.

Key use-cases in Raven:
  - Enrich threat indicators with internet-exposed service data
  - Search for vulnerable hosts matching a CVE or product/version
  - Hunt for exposed infrastructure relevant to active threats
  - Resolve IP reputation (honeyscore, open ports, banners)
  - Correlate CVE findings with real exposed hosts
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
import ipaddress


@dataclass
class ShodanHost:
    ip: str
    hostnames: List[str]
    org: str
    country: str
    ports: List[int]
    vulns: List[str]  # CVE IDs reported by Shodan
    tags: List[str]
    honeyscore: float  # 0.0–1.0 probability of being a honeypot
    banner_count: int
    asn: str = ""
    isp: str = ""
    os: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ShodanSearchResult:
    total: int
    hosts: List[ShodanHost]
    facets: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ShodanScan:
    scan_id: str
    status: str
    count: int
    credits_left: int = 0
    created: str = ""


@dataclass
class ShodanAlert:
    alert_id: str
    name: str
    filters: Dict[str, Any]
    size: int
    created: str = ""
    has_triggers: bool = False
    triggers: Dict[str, Any] = field(default_factory=dict)


class ShodanClient:
    """
    Raven wrapper around the shodan-python Shodan client.
    Provides threat-hunting-oriented methods on top of the raw API.
    """

    def __init__(self, config: Dict[str, Any]):
        api_key = config.get("shodan_api_key", "")
        if not api_key:
            raise ValueError(
                "SHODAN_API_KEY is not set. "
                "Get a free key at https://account.shodan.io"
            )
        try:
            import shodan

            self._api = shodan.Shodan(api_key)
        except ImportError:
            raise RuntimeError(
                "shodan package is not installed. " "Run: pip install shodan"
            )
        self._max_results = config.get("shodan_max_results", 100)

    # ------------------------------------------------------------------
    # Host intelligence
    # ------------------------------------------------------------------

    def host_info(
        self,
        ip: str,
        history: bool = False,
        minify: bool = False,
    ) -> ShodanHost:
        """
        Get all available Shodan data for a single IP address.
        :param minify: If True, return only ports + general info (no banners). Does not count against query credits.
        """
        from shodan.exception import APIError

        self._validate_ip(ip)
        try:
            data = self._api.host(ip, history=history, minify=minify)
        except APIError as e:
            raise RuntimeError(f"Shodan host lookup failed for {ip}: {e}")

        honeyscore = 0.0
        if not minify:
            try:
                honeyscore = float(self._api.labs.honeyscore(ip))
            except Exception:
                pass

        return ShodanHost(
            ip=data.get("ip_str", ip),
            hostnames=data.get("hostnames", []),
            org=data.get("org", ""),
            country=data.get("country_name", ""),
            ports=data.get("ports", []),
            vulns=list(data.get("vulns", {}).keys()),
            tags=data.get("tags", []),
            honeyscore=honeyscore,
            banner_count=len(data.get("data", [])),
            asn=data.get("asn", ""),
            isp=data.get("isp", ""),
            os=data.get("os"),
            raw=data,
        )

    def bulk_host_info(self, ips: List[str]) -> List[ShodanHost]:
        """Look up multiple IPs in a single Shodan API call (up to 100)."""
        from shodan.exception import APIError

        for ip in ips:
            self._validate_ip(ip)
        try:
            data = self._api.host(ips[:100])
        except APIError as e:
            raise RuntimeError(f"Shodan bulk host lookup failed: {e}")
        if isinstance(data, dict):
            data = [data]
        return [
            ShodanHost(
                ip=h.get("ip_str", ""),
                hostnames=h.get("hostnames", []),
                org=h.get("org", ""),
                country=h.get("country_name", ""),
                ports=h.get("ports", []),
                vulns=list(h.get("vulns", {}).keys()),
                tags=h.get("tags", []),
                honeyscore=0.0,
                banner_count=len(h.get("data", [])),
                raw=h,
            )
            for h in data
        ]

    # ------------------------------------------------------------------
    # Threat hunting searches
    # ------------------------------------------------------------------

    def search_cve(
        self, cve_id: str, max_results: Optional[int] = None
    ) -> ShodanSearchResult:
        """
        Find internet-exposed hosts vulnerable to a specific CVE.
        Uses Shodan's vuln: filter.
        """
        return self.search(f"vuln:{cve_id}", max_results=max_results)

    def search_product(
        self,
        product: str,
        version: Optional[str] = None,
        country: Optional[str] = None,
    ) -> ShodanSearchResult:
        """
        Search for hosts running a specific product/version.
        Example: search_product("Apache httpd", version="2.4.49")
        """
        query = f'product:"{product}"'
        if version:
            query += f' version:"{version}"'
        if country:
            query += f" country:{country}"
        return self.search(query)

    def search_open_port(
        self, port: int, banner_text: Optional[str] = None
    ) -> ShodanSearchResult:
        """Find hosts with a specific port open, optionally with matching banner text."""
        query = f"port:{port}"
        if banner_text:
            query += f" {banner_text}"
        return self.search(query)

    def search(
        self,
        query: str,
        max_results: Optional[int] = None,
        facets: Optional[List[str]] = None,
        page: int = 1,
    ) -> ShodanSearchResult:
        """
        Generic Shodan search. Returns structured ShodanSearchResult.
        Note: queries with filters consume 1 query credit per 100 results past page 1.
        """
        from shodan.exception import APIError

        limit = max_results or self._max_results
        try:
            results = self._api.search(query, page=page, facets=facets)
        except APIError as e:
            raise RuntimeError(f"Shodan search failed for '{query}': {e}")

        hosts = []
        for match in results.get("matches", [])[:limit]:
            hosts.append(
                ShodanHost(
                    ip=match.get("ip_str", ""),
                    hostnames=match.get("hostnames", []),
                    org=match.get("org", ""),
                    country=match.get("location", {}).get("country_name", ""),
                    ports=[match.get("port", 0)],
                    vulns=list(match.get("vulns", {}).keys()),
                    tags=match.get("tags", []),
                    honeyscore=0.0,
                    banner_count=1,
                    asn=match.get("asn", ""),
                    isp=match.get("isp", ""),
                    os=match.get("os"),
                    raw=match,
                )
            )

        return ShodanSearchResult(
            total=results.get("total", 0),
            hosts=hosts,
            facets=results.get("facets", {}),
        )

    def search_facets(self) -> List[str]:
        """Return the list of available search facets (free, no credits)."""
        from shodan.exception import APIError

        try:
            return self._api._request("/shodan/host/search/facets", {})
        except APIError as e:
            raise RuntimeError(f"Shodan search/facets failed: {e}")

    def search_filters(self) -> List[str]:
        """Return the list of all search filters that can be used in queries."""
        from shodan.exception import APIError

        try:
            return self._api._request("/shodan/host/search/filters", {})
        except APIError as e:
            raise RuntimeError(f"Shodan search/filters failed: {e}")

    def search_tokens(self, query: str) -> Dict[str, Any]:
        """
        Break a query string into tokens — shows which filters are active.
        Useful for validating queries before running a credit-consuming search.
        """
        from shodan.exception import APIError

        try:
            return self._api._request("/shodan/host/search/tokens", {"query": query})
        except APIError as e:
            raise RuntimeError(f"Shodan search/tokens failed: {e}")

    def count(self, query: str) -> int:
        """Return the total number of Shodan results for a query without fetching them."""
        from shodan.exception import APIError

        try:
            result = self._api.count(query)
            return result.get("total", 0)
        except APIError as e:
            raise RuntimeError(f"Shodan count failed for '{query}': {e}")

    # ------------------------------------------------------------------
    # DNS intelligence
    # ------------------------------------------------------------------

    def domain_info(self, domain: str) -> Dict[str, Any]:
        """Get DNS records and subdomains for a domain."""
        from shodan.exception import APIError

        try:
            return self._api.dns.domain_info(domain)
        except APIError as e:
            raise RuntimeError(f"Shodan DNS lookup failed for {domain}: {e}")

    def resolve(self, hostnames: List[str]) -> Dict[str, str]:
        """Resolve hostnames to IPs using Shodan's DNS resolver."""
        from shodan.exception import APIError

        try:
            return self._api.resolve(hostnames)
        except APIError as e:
            raise RuntimeError(f"Shodan resolve failed: {e}")

    def reverse_dns(self, ips: List[str]) -> Dict[str, List[str]]:
        """Reverse DNS lookup for a list of IPs."""
        from shodan.exception import APIError

        try:
            return self._api.reverse(ips)
        except APIError as e:
            raise RuntimeError(f"Shodan reverse DNS failed: {e}")

    # ------------------------------------------------------------------
    # On-demand scanning  (requires paid plan — 1 IP = 1 scan credit)
    # ------------------------------------------------------------------

    def request_scan(self, ips: List[str]) -> ShodanScan:
        """
        Request Shodan to crawl a list of IPs / CIDR netblocks.
        Requires a paid API plan. 1 IP = 1 scan credit.
        """
        from shodan.exception import APIError

        try:
            result = self._api.scan(",".join(ips))
            return ShodanScan(
                scan_id=result.get("id", ""),
                status="SUBMITTING",
                count=result.get("count", len(ips)),
                credits_left=result.get("credits_left", 0),
            )
        except APIError as e:
            raise RuntimeError(f"Shodan scan request failed: {e}")

    def scan_status(self, scan_id: str) -> ShodanScan:
        """Check the status of a previously submitted scan (SUBMITTING/QUEUE/PROCESSING/DONE)."""
        from shodan.exception import APIError

        try:
            result = self._api._request(f"/shodan/scans/{scan_id}", {})
            return ShodanScan(
                scan_id=result.get("id", scan_id),
                status=result.get("status", "UNKNOWN"),
                count=result.get("count", 0),
                created=result.get("created", ""),
            )
        except APIError as e:
            raise RuntimeError(f"Shodan scan status failed for {scan_id}: {e}")

    def list_scans(self) -> List[ShodanScan]:
        """List all on-demand scans currently active on the account."""
        from shodan.exception import APIError

        try:
            result = self._api._request("/shodan/scans", {})
            return [
                ShodanScan(
                    scan_id=s.get("id", ""),
                    status=s.get("status", ""),
                    count=s.get("size", 0),
                    credits_left=s.get("credits_left", 0),
                    created=s.get("created", ""),
                )
                for s in result.get("matches", [])
            ]
        except APIError as e:
            raise RuntimeError(f"Shodan list scans failed: {e}")

    # ------------------------------------------------------------------
    # Network alerts  (monitor owned IP ranges for new discoveries)
    # ------------------------------------------------------------------

    def create_alert(
        self,
        name: str,
        ips: List[str],
        expires: int = 0,
    ) -> ShodanAlert:
        """
        Create a network alert to monitor an IP / CIDR range.
        Shodan will notify when new services are discovered.
        :param expires: seconds until alert expires (0 = never)
        """
        from shodan.exception import APIError

        try:
            result = self._api.create_alert(name, ips, expires=expires)
            return self._parse_alert(result)
        except APIError as e:
            raise RuntimeError(f"Shodan create alert failed: {e}")

    def delete_alert(self, alert_id: str) -> bool:
        """Delete a network alert."""
        from shodan.exception import APIError

        try:
            result = self._api._request(
                f"/shodan/alert/{alert_id}", {}, method="delete"
            )
            return result.get("success", False)
        except APIError as e:
            raise RuntimeError(f"Shodan delete alert failed for {alert_id}: {e}")

    def list_alerts(self) -> List[ShodanAlert]:
        """List all active network alerts on the account."""
        from shodan.exception import APIError

        try:
            results = self._api.alerts()
            return [self._parse_alert(a) for a in (results or [])]
        except APIError as e:
            raise RuntimeError(f"Shodan list alerts failed: {e}")

    def list_alert_triggers(self) -> List[Dict[str, Any]]:
        """Return all available alert trigger types (e.g. malware, ics, open_database)."""
        from shodan.exception import APIError

        try:
            return self._api._request("/shodan/alert/triggers", {})
        except APIError as e:
            raise RuntimeError(f"Shodan list triggers failed: {e}")

    def enable_alert_trigger(self, alert_id: str, trigger: str) -> bool:
        """
        Enable a trigger on a network alert.
        :param trigger: comma-separated trigger names, e.g. "malware,open_database"
        """
        from shodan.exception import APIError

        try:
            result = self._api._request(
                f"/shodan/alert/{alert_id}/trigger/{trigger}", {}, method="put"
            )
            return result.get("success", False)
        except APIError as e:
            raise RuntimeError(f"Shodan enable trigger failed: {e}")

    def _parse_alert(self, data: Dict[str, Any]) -> ShodanAlert:
        return ShodanAlert(
            alert_id=data.get("id", ""),
            name=data.get("name", ""),
            filters=data.get("filters", {}),
            size=data.get("size", 0),
            created=data.get("created", ""),
            has_triggers=data.get("has_triggers", False),
            triggers=data.get("triggers", {}),
        )

    # ------------------------------------------------------------------
    # Exploit search
    # ------------------------------------------------------------------

    def search_exploits(self, query: str) -> List[Dict[str, Any]]:
        """
        Search the Shodan Exploits database.
        Useful for finding PoC code matching discovered CVEs.
        """
        from shodan.exception import APIError

        try:
            results = self._api.exploits.search(query)
            return results.get("matches", [])
        except APIError as e:
            raise RuntimeError(f"Shodan exploits search failed: {e}")

    # ------------------------------------------------------------------
    # Account / API key info
    # ------------------------------------------------------------------

    def api_info(self) -> Dict[str, Any]:
        """Return plan info and credits for the current API key."""
        from shodan.exception import APIError

        try:
            return self._api.info()
        except APIError as e:
            raise RuntimeError(f"Shodan API info failed: {e}")

    # ------------------------------------------------------------------
    # Raven threat hunting helpers
    # ------------------------------------------------------------------

    def enrich_threat_indicator(self, ip: str) -> Dict[str, Any]:
        """
        Enrich a threat indicator IP with Shodan context.
        Returns a flat dict suitable for attaching to a Raven Threat object.
        """
        try:
            host = self.host_info(ip)
        except RuntimeError:
            return {"ip": ip, "shodan_available": False}

        return {
            "ip": ip,
            "shodan_available": True,
            "org": host.org,
            "country": host.country,
            "open_ports": host.ports,
            "known_vulns": host.vulns,
            "tags": host.tags,
            "honeyscore": host.honeyscore,
            "is_likely_honeypot": host.honeyscore >= 0.5,
            "hostnames": host.hostnames,
        }

    def find_exposed_hosts_for_cve(self, cve_id: str) -> Dict[str, Any]:
        """
        Search Shodan for hosts exposed to a given CVE and return a
        summary suitable for Raven's threat context.
        """
        result = self.search_cve(cve_id)
        return {
            "cve_id": cve_id,
            "total_exposed": result.total,
            "sample_hosts": [
                {
                    "ip": h.ip,
                    "org": h.org,
                    "country": h.country,
                    "ports": h.ports,
                    "hostnames": h.hostnames,
                }
                for h in result.hosts[:10]
            ],
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_ip(ip: str):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError(f"Invalid IP address: {ip}")

    def serialize_host(self, host: ShodanHost) -> Dict[str, Any]:
        return {
            "ip": host.ip,
            "hostnames": host.hostnames,
            "org": host.org,
            "country": host.country,
            "ports": host.ports,
            "vulns": host.vulns,
            "tags": host.tags,
            "honeyscore": host.honeyscore,
            "banner_count": host.banner_count,
        }

    def serialize_result(self, result: ShodanSearchResult) -> Dict[str, Any]:
        return {
            "total": result.total,
            "hosts": [self.serialize_host(h) for h in result.hosts],
            "facets": result.facets,
        }
