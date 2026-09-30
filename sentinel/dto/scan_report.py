from dataclasses import dataclass
from datetime import datetime

from sentinel.dto.dependency_security_summary import DependencySecuritySummary
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.scan_status import ScanStatus
from sentinel.enums.security_status import SecurityStatus
from sentinel.enums.source_type import SourceType


@dataclass(slots=True)
class ScanReport:
    scan_id: int
    repository_id: int

    profile_name: str
    engine_version: str

    status: ScanStatus
    security_status: SecurityStatus

    started_at: datetime
    finished_at: datetime | None
    duration_seconds: int | None

    source_type: SourceType
    source_reference: str | None
    source_branch: str | None
    source_commit: str | None

    findings: list[VulnerabilityInfo]
    dependency_summaries: list[DependencySecuritySummary]

    critical_count: int
    high_count: int
    medium_count: int
    low_count: int

    risk_score: int

    error_message: str | None
