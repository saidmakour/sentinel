from dataclasses import dataclass


@dataclass(slots=True)
class DashboardSummary:
    total_scans: int
    completed_scans: int
    failed_scans: int
    total_findings: int

    findings_by_severity: dict[str, int]
