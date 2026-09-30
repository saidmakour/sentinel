from collections import defaultdict

from sentinel.dto.dependency_security_summary import DependencySecuritySummary
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.vulnerability_status import VulnerabilityStatus
from sentinel.log import get_logger
from sentinel.services.security_status_service import SecurityStatusService
from sentinel.services.version_service import VersionService

logger = get_logger(__name__)


class DependencySecurityService:
    def __init__(
        self,
        version_service: VersionService | None = None,
        security_status_service: SecurityStatusService | None = None,
    ) -> None:
        self.version_service = (
            version_service
            if version_service is not None
            else VersionService()
        )
        self.security_status_service = (
            security_status_service
            if security_status_service is not None
            else SecurityStatusService()
        )

    def summarize(
        self,
        findings: list[VulnerabilityInfo],
    ) -> list[DependencySecuritySummary]:
        grouped: dict[
            tuple[str, str, Ecosystem],
            list[VulnerabilityInfo],
        ] = defaultdict(list)

        for finding in findings:
            key = (
                finding.dependency_name,
                finding.dependency_version,
                finding.ecosystem,
            )
            grouped[key].append(finding)

        return [
            self._build_summary(
                dependency_name=dependency_name,
                installed_version=installed_version,
                ecosystem=ecosystem,
                findings=dependency_findings,
            )
            for (
                dependency_name,
                installed_version,
                ecosystem,
            ), dependency_findings in grouped.items()
        ]

    def _build_summary(
        self,
        dependency_name: str,
        installed_version: str,
        ecosystem: Ecosystem,
        findings: list[VulnerabilityInfo],
    ) -> DependencySecuritySummary:
        open_findings = [
            finding
            for finding in findings
            if finding.status == VulnerabilityStatus.OPEN
        ]

        recommended_versions: list[str] = []

        for finding in open_findings:
            logger.info(
                "DEPENDENCY=%s VERSION=%s ID=%s",
                finding.dependency_name,
                installed_version,
                finding.identifier,
            )

            if finding.remediation is None:
                logger.info("  REMEDIATION=None")
                continue

            for rule in finding.remediation.rules:
                logger.info(
                    "  RULE introduced=%s fixed=%s affected_range=%s",
                    rule.introduced,
                    rule.fixed,
                    rule.affected_range,
                )

            version = self.version_service.recommended_version(
                ecosystem=finding.ecosystem,
                installed_version=installed_version,
                remediation=finding.remediation,
            )

            if version is None:
                recommended_versions = []
                break

            recommended_versions.append(version)

        recommended_version = self._highest_version(
            ecosystem=ecosystem,
            versions=recommended_versions,
        )

        # security_status = (
        #    SecurityStatus.AT_RISK if open_findings else SecurityStatus.SECURE
        # )

        security_status = self.security_status_service.calculate(
            findings,
        )
        return DependencySecuritySummary(
            dependency_name=dependency_name,
            installed_version=installed_version,
            ecosystem=ecosystem,
            security_status=security_status,
            finding_count=len(findings),
            open_finding_count=len(open_findings),
            recommended_version=recommended_version,
        )

    def _highest_version(
        self,
        ecosystem: Ecosystem,
        versions: list[str],
    ) -> str | None:
        if not versions:
            return None

        highest = versions[0]

        for version in versions[1:]:
            if (
                self.version_service.compare_versions(
                    ecosystem=ecosystem,
                    version_a=version,
                    version_b=highest,
                )
                > 0
            ):
                highest = version

        return highest
