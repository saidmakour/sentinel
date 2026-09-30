from __future__ import annotations

from pathlib import Path

from sentinel.builders.scan_result_builder import ScanResultBuilder
from sentinel.dto.scan_result import ScanResult
from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enrichers.base import BaseEnricher
from sentinel.enrichers.executor import EnricherExecutor
from sentinel.enrichers.registry import EnricherRegistry
from sentinel.log.logger import get_logger
from sentinel.plugins.defaults import create_plugin_registry
from sentinel.profiles.base import BaseProfile
from sentinel.providers.base import BaseProvider
from sentinel.providers.executor import ProviderExecutor
from sentinel.providers.registry import ProviderRegistry
from sentinel.scanners.factory import ScannerFactory
from sentinel.services.finding_normalizer import FindingNormalizer
from sentinel.services.vulnerability_status_service import (
    VulnerabilityStatusService,
)

logger = get_logger(__name__)


class SentinelEngine:
    def __init__(
        self,
        scanner_factory: ScannerFactory | None = None,
        provider_registry: ProviderRegistry | None = None,
        provider_executor: ProviderExecutor | None = None,
        enricher_registry: EnricherRegistry | None = None,
        enricher_executor: EnricherExecutor | None = None,
        finding_normalizer: FindingNormalizer | None = None,
        vulnerability_status_service: VulnerabilityStatusService | None = None,
        scan_result_builder: ScanResultBuilder | None = None,
    ) -> None:

        self.scanner_factory = (
            scanner_factory
            if scanner_factory is not None
            else ScannerFactory(create_plugin_registry())
        )
        self.provider_registry = provider_registry or ProviderRegistry()
        self.provider_executor = provider_executor or ProviderExecutor()
        self.enricher_registry = enricher_registry or EnricherRegistry()
        self.enricher_executor = enricher_executor or EnricherExecutor()
        self.finding_normalizer = finding_normalizer or FindingNormalizer()
        self.vulnerability_status_service = (
            vulnerability_status_service or VulnerabilityStatusService()
        )
        self.scan_result_builder = scan_result_builder or ScanResultBuilder()

    def scan_dependencies(
        self,
        language: str,
        path: Path,
    ) -> list[ScannedDependency]:

        logger.info(
            "Starting dependency scan: language=%s path=%s",
            language,
            path,
        )

        scanner = self.scanner_factory.create(
            language,
        )

        dependencies = scanner.scan(
            path,
        )

        logger.info(
            "Dependency scan completed: %d dependencies found",
            len(dependencies),
        )

        return dependencies

    def find_vulnerabilities(
        self,
        dependencies: list[ScannedDependency],
        profile: BaseProfile,
    ) -> list[VulnerabilityInfo]:

        logger.info(
            "Starting vulnerability scan for %d dependencies",
            len(dependencies),
        )

        providers = self._create_providers(
            profile,
        )

        logger.debug(
            "Created %d vulnerability providers",
            len(providers),
        )

        findings = self._execute_providers(
            dependencies,
            providers,
        )

        logger.info(
            "Provider execution completed: %d findings",
            len(findings),
        )

        findings = self._normalize_findings(
            findings,
        )
        for finding in findings:
            if finding.identifier == "CVE-2026-27735":
                logger.info(
                    "BEFORE ENRICHMENT: dependency=%s version=%s "
                    "ecosystem=%s remediation=%s",
                    finding.dependency_name,
                    finding.dependency_version,
                    finding.ecosystem,
                    finding.remediation,
                )
        self._enrich_findings(
            findings,
            profile,
        )
        for finding in findings:
            if finding.identifier == "CVE-2026-27735":
                logger.info(
                    "AFTER ENRICHMENT: dependency=%s version=%s "
                    "ecosystem=%s remediation=%s",
                    finding.dependency_name,
                    finding.dependency_version,
                    finding.ecosystem,
                    finding.remediation,
                )
        findings = self._apply_vulnerability_status(
            findings,
        )
        logger.info(
            "Vulnerability scan completed: %d findings",
            len(findings),
        )

        return findings

    def run(
        self,
        language: str,
        path: Path,
        profile: BaseProfile,
    ) -> ScanResult:

        logger.info(
            "Starting Sentinel scan: language=%s path=%s",
            language,
            path,
        )

        dependencies = self.scan_dependencies(
            language,
            path,
        )

        findings = self.find_vulnerabilities(
            dependencies,
            profile,
        )

        result = self.scan_result_builder.build(
            dependencies,
            findings,
        )

        logger.info(
            "Sentinel scan completed: dependencies=%d findings=%d",
            len(dependencies),
            len(findings),
        )

        return result

    def _create_providers(
        self,
        profile: BaseProfile,
    ) -> list[BaseProvider]:

        return self.provider_registry.create(
            profile.providers,
        )

    def _execute_providers(
        self,
        dependencies: list[ScannedDependency],
        providers: list[BaseProvider],
    ) -> list[VulnerabilityInfo]:

        return [
            finding
            for dependency in dependencies
            for finding in self.provider_executor.execute(
                dependency,
                providers,
            )
        ]

    def _normalize_findings(
        self,
        findings: list[VulnerabilityInfo],
    ) -> list[VulnerabilityInfo]:

        original_count = len(findings)

        findings = self.finding_normalizer.normalize(
            findings,
        )

        logger.debug(
            "Normalized findings: %d -> %d findings",
            original_count,
            len(findings),
        )

        return findings

    def _enrich_findings(
        self,
        findings: list[VulnerabilityInfo],
        profile: BaseProfile,
    ) -> None:

        enrichers: list[BaseEnricher] = self.enricher_registry.create(
            profile.enrichers,
        )

        logger.debug(
            "Created %d enrichers",
            len(enrichers),
        )

        self.enricher_executor.execute(
            findings,
            enrichers,
        )

        logger.debug(
            "Enrichment completed for %d findings",
            len(findings),
        )

    def _apply_vulnerability_status(
        self,
        findings: list[VulnerabilityInfo],
    ) -> list[VulnerabilityInfo]:

        result: list[VulnerabilityInfo] = []

        for finding in findings:
            status = self.vulnerability_status_service.apply(
                finding,
            )

            if finding.identifier.startswith("CVE-"):
                logger.info(
                    "STATUS RESULT: id=%s dependency=%s version=%s "
                    "ecosystem=%s status=%s remediation=%s fixed_versions=%s",
                    finding.identifier,
                    finding.dependency_name,
                    finding.dependency_version,
                    finding.ecosystem,
                    finding.status,
                    finding.remediation,
                    finding.fixed_versions,
                )

            result.append(status)

        return result
