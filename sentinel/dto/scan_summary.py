from dataclasses import dataclass

from sentinel.dto.severity_summary import SeveritySummary
from sentinel.enums.scan_status import ScanStatus
from sentinel.enums.source_type import SourceType


@dataclass(slots=True)
class ScanSummary:
    scan_id: int
    status: ScanStatus

    dependency_count: int
    finding_count: int

    duration_seconds: int | None

    severity: SeveritySummary
    vulnerability_status: dict[str, int]

    source_type: SourceType
    source_reference: str | None
