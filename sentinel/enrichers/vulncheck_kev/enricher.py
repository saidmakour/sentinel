from __future__ import annotations

from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enrichers.base import BaseEnricher
from sentinel.enrichers.vulncheck_kev.client import VulnCheckKEVClient


class VulnCheckKEVEnricher(BaseEnricher):
    """
    Enrich vulnerabilities with VulnCheck KEV information.
    """

    def __init__(
        self,
        client: VulnCheckKEVClient | None = None,
    ) -> None:
        self.client = client or VulnCheckKEVClient()

    def enrich(
        self,
        findings: list[VulnerabilityInfo],
    ) -> None:
        catalog = self.client.load()

        for finding in findings:
            vulnerability = catalog.get(
                finding.identifier,
            )

            if vulnerability is None:
                continue

            finding.vulncheck_known_exploited = True
            finding.vulncheck_date_added = vulnerability.date_added
            finding.vulncheck_cisa_date_added = vulnerability.cisa_date_added
            finding.vulncheck_due_date = vulnerability.due_date
            finding.vulncheck_vendor = vulnerability.vendor
            finding.vulncheck_product = vulnerability.product
            finding.vulncheck_required_action = vulnerability.required_action
            finding.vulncheck_known_ransomware = vulnerability.known_ransomware
            finding.vulncheck_reported_exploited_by_canaries = (
                vulnerability.reported_exploited_by_canaries
            )
