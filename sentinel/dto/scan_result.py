from dataclasses import dataclass

from sentinel.dto.dependency_security_summary import DependencySecuritySummary
from sentinel.dto.scan_statistics import ScanStatistics
from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.dto.vulnerability_info import VulnerabilityInfo


@dataclass(slots=True)
class ScanResult:
    dependencies: list[ScannedDependency]
    findings: list[VulnerabilityInfo]

    statistics: ScanStatistics
    dependency_summaries: list[DependencySecuritySummary]
