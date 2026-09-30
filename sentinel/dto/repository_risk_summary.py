from dataclasses import dataclass


@dataclass(slots=True)
class RepositoryRiskSummary:
    repository_id: int
    repository_name: str
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    total_findings: int
    risk_score: int
