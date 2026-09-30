# tests/api/mappers/test_dashboard_risk.py

from sentinel.api.mappers.dashboard_mapper import dashboard_risk_to_schema
from sentinel.api.schemas.dashboard import DashboardRiskSummarySchema
from sentinel.dto.dashboard_risk_summary import DashboardRiskSummary


def test_dashboard_risk_to_schema_maps_all_fields() -> None:
    summary = DashboardRiskSummary(
        total_findings=128,
        critical_count=7,
        high_count=19,
        medium_count=41,
        low_count=61,
        risk_score=84,
        repositories_at_risk=12,
    )

    result = dashboard_risk_to_schema(summary)

    assert isinstance(result, DashboardRiskSummarySchema)
    assert result.total_findings == 128
    assert result.critical_count == 7
    assert result.high_count == 19
    assert result.medium_count == 41
    assert result.low_count == 61
    assert result.risk_score == 84
    assert result.repositories_at_risk == 12
