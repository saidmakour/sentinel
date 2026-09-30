from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enrichers.base import BaseEnricher
from sentinel.log.logger import get_logger

logger = get_logger(__name__)


class EnricherExecutor:
    def execute(
        self,
        findings: list[VulnerabilityInfo],
        enrichers: list[BaseEnricher],
    ) -> list[VulnerabilityInfo]:

        if not findings:
            logger.debug(
                "Skipping enrichment: no findings.",
            )
            return []

        if not enrichers:
            logger.debug(
                "Skipping enrichment: no enrichers configured.",
            )
            return findings

        for enricher in enrichers:
            logger.debug(
                "Running enricher: enricher=%s findings=%d",
                type(enricher).__name__,
                len(findings),
            )
            enricher.enrich(
                findings,
            )

        logger.debug(
            "Enrichment completed: findings=%d",
            len(findings),
        )
        return findings
