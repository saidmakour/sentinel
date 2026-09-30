from dataclasses import dataclass

from sentinel.dto.severity_summary import SeveritySummary


@dataclass(slots=True)
class ScanStatistics:
    dependency_count: int
    finding_count: int
    severity: SeveritySummary
    status: dict[str, int]
