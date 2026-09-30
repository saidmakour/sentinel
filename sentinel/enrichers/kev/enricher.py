from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enrichers.base import BaseEnricher
from sentinel.enrichers.kev.client import KEVClient


class KEVEnricher(BaseEnricher):
    def __init__(
        self,
        client: KEVClient | None = None,
    ) -> None:
        self.client = client or KEVClient()

    def enrich(
        self,
        findings: list[VulnerabilityInfo],
    ) -> None:
        catalog = self.client.load()

        for finding in findings:
            kev = catalog.get(
                finding.identifier,
            )

            if kev is None:
                continue

            finding.known_exploited = True
            finding.kev_date_added = kev.date_added
            finding.kev_vendor = kev.vendor
            finding.kev_product = kev.product
            finding.kev_known_ransomware = kev.known_ransomware
            finding.kev_required_action = kev.required_action
