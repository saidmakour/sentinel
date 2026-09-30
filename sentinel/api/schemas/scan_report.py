from datetime import datetime

from pydantic import BaseModel

from sentinel.api.schemas.vulnerability import VulnerabilityInfoSchema
from sentinel.enums.scan_status import ScanStatus
from sentinel.enums.security_status import SecurityStatus
from sentinel.enums.source_type import SourceType


class ScanReportSchema(BaseModel):
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

    findings: list[VulnerabilityInfoSchema]

    critical_count: int
    high_count: int
    medium_count: int
    low_count: int

    risk_score: int

    error_message: str | None
