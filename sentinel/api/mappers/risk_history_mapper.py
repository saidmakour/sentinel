from sentinel.api.schemas.risk_history import RiskHistoryPointSchema
from sentinel.dto.risk_history import RiskHistoryPoint


def risk_history_to_schema(
    points: list[RiskHistoryPoint],
) -> list[RiskHistoryPointSchema]:

    return [
        RiskHistoryPointSchema(
            scan_id=point.scan_id,
            date=point.date,
            critical=point.critical,
            high=point.high,
            medium=point.medium,
            low=point.low,
            risk_score=point.risk_score,
        )
        for point in points
    ]
