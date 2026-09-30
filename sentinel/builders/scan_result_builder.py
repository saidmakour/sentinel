from collections import Counter

from sentinel.dto.scan_result import ScanResult
from sentinel.dto.scan_statistics import ScanStatistics
from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.dto.severity_summary import SeveritySummary
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.severity import Severity
from sentinel.services.dependency_security_service import (
    DependencySecurityService,
)


class ScanResultBuilder:
    def __init__(
        self,
        dependency_security_service: (DependencySecurityService | None) = None,
    ) -> None:
        self.dependency_security_service = (
            dependency_security_service
            if dependency_security_service is not None
            else DependencySecurityService()
        )

    def build(
        self,
        dependencies: list[ScannedDependency],
        findings: list[VulnerabilityInfo],
    ) -> ScanResult:

        severity = self._build_severity(findings)
        status = dict(Counter(finding.status.value for finding in findings))

        dependency_summaries = self.dependency_security_service.summarize(
            findings,
        )

        return ScanResult(
            dependencies=dependencies,
            findings=findings,
            statistics=ScanStatistics(
                dependency_count=len(dependencies),
                finding_count=len(findings),
                severity=severity,
                status=status,
            ),
            dependency_summaries=dependency_summaries,
        )

    def _build_severity(
        self,
        findings: list[VulnerabilityInfo],
    ) -> SeveritySummary:

        summary = SeveritySummary()

        for finding in findings:
            match finding.severity:
                case Severity.CRITICAL:
                    summary.critical += 1

                case Severity.HIGH:
                    summary.high += 1

                case Severity.MEDIUM:
                    summary.medium += 1

                case Severity.LOW:
                    summary.low += 1

                case Severity.UNKNOWN:
                    summary.unknown += 1

        return summary
