from unittest.mock import MagicMock

from sentinel.dto.risk_history import RiskHistoryPoint
from sentinel.services.risk_trend_service import RiskTrendService


def create_history_point(
    *,
    scan_id: int,
    risk_score: int,
) -> RiskHistoryPoint:
    return RiskHistoryPoint(
        scan_id=scan_id,
        date=None,
        critical=0,
        high=0,
        medium=0,
        low=0,
        risk_score=risk_score,
    )


def create_service(
    monkeypatch,
    *,
    history: list[RiskHistoryPoint],
) -> tuple[
    RiskTrendService,
    MagicMock,
]:
    session = MagicMock()

    history_service = MagicMock()

    history_service.get_history.return_value = history

    monkeypatch.setattr(
        "sentinel.services.risk_trend_service.RiskHistoryService",
        lambda session: history_service,
    )

    service = RiskTrendService(
        session,
    )

    return (
        service,
        history_service,
    )


def test_get_trend_returns_unknown_when_history_is_empty(
    monkeypatch,
) -> None:
    service, history_service = create_service(
        monkeypatch,
        history=[],
    )

    result = service.get_trend(
        repository_id=1,
    )

    assert result.current_score == 0
    assert result.previous_score is None
    assert result.delta == 0
    assert result.trend == "unknown"

    history_service.get_history.assert_called_once_with(
        1,
    )


def test_get_trend_returns_unknown_with_single_scan(
    monkeypatch,
) -> None:
    history = [
        create_history_point(
            scan_id=1,
            risk_score=25,
        ),
    ]

    service, _ = create_service(
        monkeypatch,
        history=history,
    )

    result = service.get_trend(
        repository_id=1,
    )

    assert result.current_score == 25
    assert result.previous_score is None
    assert result.delta == 0
    assert result.trend == "unknown"


def test_get_trend_returns_improving_when_risk_decreases(
    monkeypatch,
) -> None:
    history = [
        create_history_point(
            scan_id=1,
            risk_score=30,
        ),
        create_history_point(
            scan_id=2,
            risk_score=20,
        ),
    ]

    service, _ = create_service(
        monkeypatch,
        history=history,
    )

    result = service.get_trend(
        repository_id=1,
    )

    assert result.current_score == 20
    assert result.previous_score == 30
    assert result.delta == -10
    assert result.trend == "improving"


def test_get_trend_returns_degrading_when_risk_increases(
    monkeypatch,
) -> None:
    history = [
        create_history_point(
            scan_id=1,
            risk_score=20,
        ),
        create_history_point(
            scan_id=2,
            risk_score=30,
        ),
    ]

    service, _ = create_service(
        monkeypatch,
        history=history,
    )

    result = service.get_trend(
        repository_id=1,
    )

    assert result.current_score == 30
    assert result.previous_score == 20
    assert result.delta == 10
    assert result.trend == "degrading"


def test_get_trend_returns_stable_when_risk_is_unchanged(
    monkeypatch,
) -> None:
    history = [
        create_history_point(
            scan_id=1,
            risk_score=25,
        ),
        create_history_point(
            scan_id=2,
            risk_score=25,
        ),
    ]

    service, _ = create_service(
        monkeypatch,
        history=history,
    )

    result = service.get_trend(
        repository_id=1,
    )

    assert result.current_score == 25
    assert result.previous_score == 25
    assert result.delta == 0
    assert result.trend == "stable"
