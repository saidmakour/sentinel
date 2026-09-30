from sentinel.api.schemas.risk_trend import RiskTrendSchema
from sentinel.dto.risk_trend import RiskTrend


def risk_trend_to_schema(
    trend: RiskTrend,
) -> RiskTrendSchema:

    return RiskTrendSchema(
        current_score=trend.current_score,
        previous_score=trend.previous_score,
        delta=trend.delta,
        trend=trend.trend,
    )
