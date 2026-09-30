from datetime import UTC
from datetime import datetime
from unittest.mock import MagicMock

from sentinel.enums.scan_status import ScanStatus
from sentinel.enums.severity import Severity
from sentinel.models.scan import Scan
from sentinel.services.risk_history_service import RiskHistoryService


def create_scan(
    *,
    scan_id: int,
    started_at: datetime,
    findings: list | None = None,
) -> Scan:
    scan = Scan(
        id=scan_id,
        repository_id=1,
        status=ScanStatus.SUCCESS,
        started_at=started_at,
    )

    scan.findings = findings or []

    return scan


def create_finding(
    severity: Severity,
) -> MagicMock:
    finding = MagicMock()
    finding.severity = severity.value

    return finding


def create_service(
    monkeypatch,
    *,
    scans: list[Scan] | None = None,
    risk_result: tuple[int, int, int, int, int] = (
        1,
        2,
        3,
        4,
        25,
    ),
) -> tuple[
    RiskHistoryService,
    MagicMock,
    MagicMock,
]:
    session = MagicMock()

    scan_repository = MagicMock()
    scan_repository.list_by_repository.return_value = (
        scans if scans is not None else []
    )

    monkeypatch.setattr(
        "sentinel.services.risk_history_service.ScanRepository",
        lambda session: scan_repository,
    )

    risk_service = MagicMock()
    risk_service.calculate.return_value = risk_result

    monkeypatch.setattr(
        "sentinel.services.risk_history_service.RiskService",
        lambda: risk_service,
    )

    service = RiskHistoryService(session)

    return (
        service,
        scan_repository,
        risk_service,
    )


def test_risk_history_service_can_be_created(
    monkeypatch,
) -> None:
    service, _, _ = create_service(
        monkeypatch,
    )

    assert service is not None
    assert service.scan_repo is not None
    assert service.risk_service is not None


def test_get_history_loads_scans_for_repository(
    monkeypatch,
) -> None:
    service, scan_repository, _ = create_service(
        monkeypatch,
    )

    service.get_history(
        repository_id=42,
    )

    scan_repository.list_by_repository.assert_called_once_with(
        42,
    )


def test_get_history_returns_empty_list_when_no_scans(
    monkeypatch,
) -> None:
    service, _, risk_service = create_service(
        monkeypatch,
        scans=[],
    )

    result = service.get_history(
        repository_id=1,
    )

    assert result == []

    risk_service.calculate.assert_not_called()


def test_get_history_calculates_risk_for_findings(
    monkeypatch,
) -> None:
    scan = create_scan(
        scan_id=1,
        started_at=datetime(
            2026,
            1,
            1,
            tzinfo=UTC,
        ),
        findings=[
            create_finding(Severity.CRITICAL),
            create_finding(Severity.HIGH),
            create_finding(Severity.HIGH),
            create_finding(Severity.MEDIUM),
            create_finding(Severity.LOW),
        ],
    )

    service, _, risk_service = create_service(
        monkeypatch,
        scans=[scan],
    )

    service.get_history(
        repository_id=1,
    )

    risk_service.calculate.assert_called_once_with(
        {
            Severity.CRITICAL.value: 1,
            Severity.HIGH.value: 2,
            Severity.MEDIUM.value: 1,
            Severity.LOW.value: 1,
        }
    )


def test_get_history_builds_risk_history_point(
    monkeypatch,
) -> None:
    started_at = datetime(
        2026,
        1,
        1,
        tzinfo=UTC,
    )

    scan = create_scan(
        scan_id=42,
        started_at=started_at,
    )

    service, _, _ = create_service(
        monkeypatch,
        scans=[scan],
        risk_result=(
            2,
            3,
            4,
            5,
            48,
        ),
    )

    result = service.get_history(
        repository_id=1,
    )

    assert len(result) == 1

    point = result[0]

    assert point.scan_id == 42
    assert point.date == started_at
    assert point.critical == 2
    assert point.high == 3
    assert point.medium == 4
    assert point.low == 5
    assert point.risk_score == 48


def test_get_history_returns_scans_in_chronological_order(
    monkeypatch,
) -> None:
    older_scan = create_scan(
        scan_id=1,
        started_at=datetime(
            2026,
            1,
            1,
            tzinfo=UTC,
        ),
    )

    newer_scan = create_scan(
        scan_id=2,
        started_at=datetime(
            2026,
            1,
            2,
            tzinfo=UTC,
        ),
    )

    service, _, _ = create_service(
        monkeypatch,
        # Simule un repository qui retourne les scans
        # du plus récent au plus ancien.
        scans=[
            newer_scan,
            older_scan,
        ],
    )

    result = service.get_history(
        repository_id=1,
    )

    assert [point.scan_id for point in result] == [
        1,
        2,
    ]
