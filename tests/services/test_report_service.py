from unittest.mock import MagicMock

import pytest

from sentinel.dto.scan_summary import ScanSummary
from sentinel.enums.scan_status import ScanStatus
from sentinel.exceptions.scan import NoScansFoundError
from sentinel.exceptions.scan import ScanNotFoundError
from sentinel.models.scan import Scan
from sentinel.services.report_service import ReportService


def create_scan(
    *,
    scan_id: int = 1,
) -> Scan:
    scan = MagicMock(spec=Scan)

    scan.id = scan_id
    scan.status = ScanStatus.SUCCESS
    scan.source_type = "local"
    scan.source_reference = "/tmp/project"
    scan.duration_seconds = 42

    return scan


def create_finding(
    severity: str,
) -> MagicMock:
    finding = MagicMock()

    finding.severity = severity

    return finding


def create_service() -> tuple[
    ReportService,
    MagicMock,
]:
    session = MagicMock()

    service = ReportService(
        session,
    )

    return service, session


def test_report_service_can_be_created() -> None:
    service, _ = create_service()

    assert service is not None


def test_get_scan_summary_returns_summary() -> None:
    service, session = create_service()

    scan = create_scan(
        scan_id=1,
    )

    dependency_query = MagicMock()
    dependency_query.filter.return_value.scalar.return_value = 3

    finding_query = MagicMock()
    finding_query.filter.return_value.all.return_value = []

    session.get.return_value = scan

    session.query.side_effect = [
        dependency_query,
        finding_query,
    ]

    result = service.get_scan_summary(
        scan_id=1,
    )

    assert isinstance(
        result,
        ScanSummary,
    )

    assert result.scan_id == 1
    assert result.status == ScanStatus.SUCCESS
    assert result.source_type == "local"
    assert result.source_reference == "/tmp/project"
    assert result.dependency_count == 3
    assert result.finding_count == 0
    assert result.duration_seconds == 42


def test_get_scan_summary_raises_when_scan_not_found() -> None:
    service, session = create_service()

    session.get.return_value = None

    with pytest.raises(
        ScanNotFoundError,
        match="Scan '999' not found",
    ):
        service.get_scan_summary(
            scan_id=999,
        )

    session.get.assert_called_once_with(
        Scan,
        999,
    )

    session.query.assert_not_called()


def test_get_scan_summary_counts_dependencies() -> None:
    service, session = create_service()

    scan = create_scan()

    dependency_query = MagicMock()
    dependency_query.filter.return_value.scalar.return_value = 5

    finding_query = MagicMock()
    finding_query.filter.return_value.all.return_value = []

    session.get.return_value = scan

    session.query.side_effect = [
        dependency_query,
        finding_query,
    ]

    result = service.get_scan_summary(
        scan_id=1,
    )

    assert result.dependency_count == 5

    dependency_query.filter.assert_called_once()
    dependency_query.filter.return_value.scalar.assert_called_once_with()


def test_get_scan_summary_counts_findings() -> None:
    service, session = create_service()

    scan = create_scan()

    findings = [
        create_finding("HIGH"),
        create_finding("LOW"),
        create_finding("MEDIUM"),
    ]

    dependency_query = MagicMock()
    dependency_query.filter.return_value.scalar.return_value = 0

    finding_query = MagicMock()
    finding_query.filter.return_value.all.return_value = findings

    session.get.return_value = scan

    session.query.side_effect = [
        dependency_query,
        finding_query,
    ]

    result = service.get_scan_summary(
        scan_id=1,
    )

    assert result.finding_count == 3


def test_get_scan_summary_counts_all_severities() -> None:
    service, session = create_service()

    scan = create_scan()

    findings = [
        create_finding("CRITICAL"),
        create_finding("HIGH"),
        create_finding("HIGH"),
        create_finding("MEDIUM"),
        create_finding("LOW"),
        create_finding("UNKNOWN"),
    ]

    dependency_query = MagicMock()
    dependency_query.filter.return_value.scalar.return_value = 2

    finding_query = MagicMock()
    finding_query.filter.return_value.all.return_value = findings

    session.get.return_value = scan

    session.query.side_effect = [
        dependency_query,
        finding_query,
    ]

    result = service.get_scan_summary(
        scan_id=1,
    )

    severity = result.severity

    assert severity.critical == 1
    assert severity.high == 2
    assert severity.medium == 1
    assert severity.low == 1
    assert severity.unknown == 1


def test_get_scan_summary_accepts_lowercase_severities() -> None:
    service, session = create_service()

    scan = create_scan()

    findings = [
        create_finding("critical"),
        create_finding("high"),
        create_finding("medium"),
        create_finding("low"),
    ]

    dependency_query = MagicMock()
    dependency_query.filter.return_value.scalar.return_value = 0

    finding_query = MagicMock()
    finding_query.filter.return_value.all.return_value = findings

    session.get.return_value = scan

    session.query.side_effect = [
        dependency_query,
        finding_query,
    ]

    result = service.get_scan_summary(
        scan_id=1,
    )

    assert result.severity.critical == 1
    assert result.severity.high == 1
    assert result.severity.medium == 1
    assert result.severity.low == 1


def test_get_scan_summary_unknown_severity() -> None:
    service, session = create_service()

    scan = create_scan()

    findings = [
        create_finding("INVALID"),
    ]

    dependency_query = MagicMock()
    dependency_query.filter.return_value.scalar.return_value = 0

    finding_query = MagicMock()
    finding_query.filter.return_value.all.return_value = findings

    session.get.return_value = scan

    session.query.side_effect = [
        dependency_query,
        finding_query,
    ]

    result = service.get_scan_summary(
        scan_id=1,
    )

    assert result.severity.unknown == 1


def test_get_scan_summary_with_no_findings() -> None:
    service, session = create_service()

    scan = create_scan()

    dependency_query = MagicMock()
    dependency_query.filter.return_value.scalar.return_value = 0

    finding_query = MagicMock()
    finding_query.filter.return_value.all.return_value = []

    session.get.return_value = scan

    session.query.side_effect = [
        dependency_query,
        finding_query,
    ]

    result = service.get_scan_summary(
        scan_id=1,
    )

    assert result.finding_count == 0
    assert result.severity.critical == 0
    assert result.severity.high == 0
    assert result.severity.medium == 0
    assert result.severity.low == 0
    assert result.severity.unknown == 0


def test_get_latest_summary_returns_latest_scan() -> None:
    service, session = create_service()

    latest_scan = create_scan(
        scan_id=42,
    )

    latest_query = MagicMock()
    latest_query.order_by.return_value.first.return_value = latest_scan

    session.query.return_value = latest_query

    expected_summary = MagicMock(
        spec=ScanSummary,
    )

    service.get_scan_summary = MagicMock(
        return_value=expected_summary,
    )

    result = service.get_latest_summary()

    assert result is expected_summary

    service.get_scan_summary.assert_called_once_with(
        42,
    )


def test_get_latest_summary_raises_when_no_scans() -> None:
    service, session = create_service()

    latest_query = MagicMock()
    latest_query.order_by.return_value.first.return_value = None

    session.query.return_value = latest_query

    with pytest.raises(
        NoScansFoundError,
        match="No scans found",
    ):
        service.get_latest_summary()

    service.get_scan_summary = MagicMock()

    service.get_scan_summary.assert_not_called()


def test_get_history_returns_summaries() -> None:
    service, session = create_service()

    scan1 = create_scan(
        scan_id=1,
    )

    scan2 = create_scan(
        scan_id=2,
    )

    history_query = MagicMock()

    history_query.order_by.return_value.limit.return_value.all.return_value = [
        scan1,
        scan2,
    ]

    session.query.return_value = history_query

    summary1 = MagicMock(
        spec=ScanSummary,
    )

    summary2 = MagicMock(
        spec=ScanSummary,
    )

    service.get_scan_summary = MagicMock(
        side_effect=[
            summary1,
            summary2,
        ],
    )

    result = service.get_history()

    assert result == [
        summary1,
        summary2,
    ]

    assert service.get_scan_summary.call_count == 2

    service.get_scan_summary.assert_any_call(
        1,
    )

    service.get_scan_summary.assert_any_call(
        2,
    )


def test_get_history_with_no_scans() -> None:
    service, session = create_service()

    history_query = MagicMock()

    history_query.order_by.return_value.limit.return_value.all.return_value = []

    session.query.return_value = history_query

    service.get_scan_summary = MagicMock()

    result = service.get_history()

    assert result == []

    service.get_scan_summary.assert_not_called()


def test_get_history_respects_limit() -> None:
    service, session = create_service()

    history_query = MagicMock()

    history_query.order_by.return_value.limit.return_value.all.return_value = []

    session.query.return_value = history_query

    service.get_history(
        limit=5,
    )

    history_query.order_by.return_value.limit.assert_called_once_with(
        5,
    )
