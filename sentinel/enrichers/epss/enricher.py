from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enrichers.base import BaseEnricher
from sentinel.enrichers.epss.client import EPSSClient


class EPSSEnricher(BaseEnricher):
    def __init__(
        self,
        client: EPSSClient | None = None,
    ) -> None:
        self.client = client or EPSSClient()

    def enrich(
        self,
        findings: list[VulnerabilityInfo],
    ) -> None:

        if not findings:
            return

        identifiers = list({finding.identifier for finding in findings})

        catalog = self.client.load(
            identifiers,
        )

        for finding in findings:
            epss = catalog.get(
                finding.identifier,
            )

            if epss is None:
                continue

            finding.epss_score = epss.score
            finding.epss_percentile = epss.percentile
