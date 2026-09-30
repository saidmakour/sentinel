from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.log.logger import get_logger
from sentinel.providers.base import BaseProvider
from sentinel.providers.cache import ProviderCache

logger = get_logger(__name__)


class ProviderExecutor:
    def __init__(
        self,
        cache: ProviderCache | None = None,
    ) -> None:
        self.cache = cache or ProviderCache()

    def _execute_provider(
        self,
        provider: BaseProvider,
        dependency: ScannedDependency,
    ) -> list[VulnerabilityInfo]:

        logger.debug(
            "Running provider: provider=%s dependency=%s version=%s",
            provider.name,
            dependency.name,
            dependency.version,
        )

        cached = self.cache.get(
            provider.name,
            dependency,
        )

        if cached is not None:
            logger.debug(
                "Provider cache hit: provider=%s dependency=%s version=%s",
                provider.name,
                dependency.name,
                dependency.version,
            )
            return cached

        logger.debug(
            "Provider cache miss: provider=%s dependency=%s version=%s",
            provider.name,
            dependency.name,
            dependency.version,
        )

        results = provider.scan(
            dependency,
        )
        logger.debug(
            "Provider raw results: provider=%s dependency=%s count=%d ids=%s",
            provider.name,
            dependency.name,
            len(results),
            [finding.identifier for finding in results],
        )
        self.cache.set(
            provider.name,
            dependency,
            results,
        )

        logger.debug(
            "Provider completed: provider=%s dependency=%s "
            "version=%s vulnerabilities=%d",
            provider.name,
            dependency.name,
            dependency.version,
            len(results),
        )

        return results

    def execute(
        self,
        dependency: ScannedDependency,
        providers: list[BaseProvider],
    ) -> list[VulnerabilityInfo]:

        if not providers:
            logger.debug(
                "No providers available for dependency=%s",
                dependency.name,
            )
            return []

        findings: list[VulnerabilityInfo] = []

        logger.debug(
            "Executing providers: dependency=%s version=%s providers=%d",
            dependency.name,
            dependency.version,
            len(providers),
        )

        with ThreadPoolExecutor(
            max_workers=len(providers),
        ) as executor:
            future_to_provider = {
                executor.submit(
                    self._execute_provider,
                    provider,
                    dependency,
                ): provider
                for provider in providers
            }

            for future in as_completed(
                future_to_provider,
            ):
                provider = future_to_provider[future]

                try:
                    results = future.result()

                    findings.extend(
                        results,
                    )

                except Exception:
                    logger.exception(
                        "Provider failed: provider=%s "
                        "dependency=%s version=%s",
                        provider.name,
                        dependency.name,
                        dependency.version,
                    )

        logger.debug(
            "Provider execution completed: dependency=%s "
            "version=%s findings=%d",
            dependency.name,
            dependency.version,
            len(findings),
        )

        return findings
