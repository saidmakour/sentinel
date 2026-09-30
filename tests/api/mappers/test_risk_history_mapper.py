# tests/api/mappers/test_risk_history.py
from datetime import datetime

from sentinel.api.mappers.risk_history_mapper import risk_history_to_schema
from sentinel.api.schemas.risk_history import RiskHistoryPointSchema
from sentinel.dto.risk_history import RiskHistoryPoint

# tests/api/mappers/test_risk_history.py


def test_risk_history_to_schema_maps_all_points_in_order() -> None:
    points = [
        RiskHistoryPoint(
            scan_id=1,
            date=datetime(2026, 7, 20, 9, 30, 0),
            critical=2,
            high=5,
            medium=8,
            low=13,
            risk_score=91,
        ),
        RiskHistoryPoint(
            scan_id=2,
            date=datetime(2026, 7, 21, 14, 45, 0),
            critical=1,
            high=4,
            medium=7,
            low=10,
            risk_score=87,
        ),
    ]

    result = risk_history_to_schema(points)

    assert result == [
        RiskHistoryPointSchema(
            scan_id=1,
            date=datetime(2026, 7, 20, 9, 30, 0),
            critical=2,
            high=5,
            medium=8,
            low=13,
            risk_score=91,
        ),
        RiskHistoryPointSchema(
            scan_id=2,
            date=datetime(2026, 7, 21, 14, 45, 0),
            critical=1,
            high=4,
            medium=7,
            low=10,
            risk_score=87,
        ),
    ]


def test_risk_history_to_schema_returns_empty_list_for_empty_input() -> None:
    assert risk_history_to_schema([]) == []
