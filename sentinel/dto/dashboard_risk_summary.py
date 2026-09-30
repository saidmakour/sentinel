from dataclasses import dataclass


@dataclass(slots=True)
class DashboardRiskSummary:
    total_findings: int

    critical_count: int
    high_count: int
    medium_count: int
    low_count: int

    risk_score: int

    repositories_at_risk: int
