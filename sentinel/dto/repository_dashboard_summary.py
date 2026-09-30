from dataclasses import dataclass


@dataclass(slots=True)
class RepositoryDashboardSummary:
    repository_id: int
    total_scans: int
    total_findings: int
    last_scan_status: str | None
    last_scan_profile: str | None
