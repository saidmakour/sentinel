from sentinel.api.schemas.dashboard import DashboardRiskSummarySchema
from sentinel.dto.dashboard_risk_summary import DashboardRiskSummary


def dashboard_risk_to_schema(
    summary: DashboardRiskSummary,
) -> DashboardRiskSummarySchema:

    return DashboardRiskSummarySchema(
        total_findings=summary.total_findings,
        critical_count=summary.critical_count,
        high_count=summary.high_count,
        medium_count=summary.medium_count,
        low_count=summary.low_count,
        risk_score=summary.risk_score,
        repositories_at_risk=summary.repositories_at_risk,
    )
