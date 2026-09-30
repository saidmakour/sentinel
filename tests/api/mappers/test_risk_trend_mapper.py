# tests/api/mappers/test_risk_trend.py

from sentinel.api.mappers.risk_trend_mapper import risk_trend_to_schema
from sentinel.api.schemas.risk_trend import RiskTrendSchema
from sentinel.dto.risk_trend import RiskTrend


def test_risk_trend_to_schema_maps_all_fields() -> None:
    trend = RiskTrend(
        current_score=72,
        previous_score=65,
        delta=7,
        trend="up",
    )

    result = risk_trend_to_schema(trend)

    assert isinstance(result, RiskTrendSchema)
    assert result.current_score == 72
    assert result.previous_score == 65
    assert result.delta == 7
    assert result.trend == "up"
