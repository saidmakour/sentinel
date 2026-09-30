from dataclasses import dataclass

from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.security_status import SecurityStatus


@dataclass(slots=True)
class DependencySecuritySummary:
    dependency_name: str
    installed_version: str
    ecosystem: Ecosystem
    security_status: SecurityStatus
    finding_count: int
    open_finding_count: int
    recommended_version: str | None
