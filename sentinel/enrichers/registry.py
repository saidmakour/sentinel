from __future__ import annotations

from collections.abc import Callable

from sentinel.config.settings import settings
from sentinel.enrichers.base import BaseEnricher
from sentinel.enrichers.epss.enricher import EPSSEnricher
from sentinel.enrichers.kev.enricher import KEVEnricher
from sentinel.enrichers.vulncheck_kev.enricher import VulnCheckKEVEnricher
from sentinel.enums.enricher import Enricher
from sentinel.log.logger import get_logger

logger = get_logger(__name__)


class EnricherRegistry:
    def __init__(self) -> None:

        self._registry: dict[
            Enricher,
            tuple[bool, Callable[[], BaseEnricher]],
        ] = {
            Enricher.KEV: (
                settings.kev_enabled,
                KEVEnricher,
            ),
            Enricher.EPSS: (
                settings.epss_enabled,
                EPSSEnricher,
            ),
            Enricher.VULNCHECK_KEV: (
                settings.vulncheck_kev_enabled,
                VulnCheckKEVEnricher,
            ),
        }

    def create(
        self,
        enrichers: list[Enricher],
    ) -> list[BaseEnricher]:

        result: list[BaseEnricher] = []

        for enricher in enrichers:
            entry = self._registry.get(
                enricher,
            )

            if not entry:
                logger.debug(
                    "Enricher '%s' is not registered.",
                    enricher,
                )
                continue

            enabled, factory = entry

            if not enabled:
                logger.debug(
                    "Enricher '%s' is disabled.",
                    enricher,
                )
                continue

            instance = factory()

            result.append(
                instance,
            )

            logger.debug(
                "Enricher '%s' created.",
                enricher,
            )

        return result
