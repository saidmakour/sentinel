from unittest.mock import MagicMock

from typer.testing import CliRunner

from sentinel.cli import scan_cli
from sentinel.cli.app import app

runner = CliRunner()


def create_mocks(
    monkeypatch,
    *,
    scan_id: int = 42,
) -> tuple[
    MagicMock,
    MagicMock,
    MagicMock,
    MagicMock,
]:
    session = MagicMock()

    scan = MagicMock()
    scan.id = scan_id

    scan_service = MagicMock()
    scan_service.run.return_value = scan

    report_service = MagicMock()

    report = MagicMock()

    report_service.get_scan_summary.return_value = report

    renderer = MagicMock()

    monkeypatch.setattr(
        "sentinel.cli.scan_cli.SessionLocal",
        lambda: session,
    )

    monkeypatch.setattr(
        "sentinel.cli.scan_cli.ScanService",
        lambda session: scan_service,
    )

    monkeypatch.setattr(
        "sentinel.cli.scan_cli.ReportService",
        lambda session: report_service,
    )

    monkeypatch.setattr(
        "sentinel.cli.scan_cli.ScanSummaryRenderer",
        renderer,
    )

    return (
        session,
        scan_service,
        report_service,
        renderer,
    )


def test_run_scan_success(
    monkeypatch,
) -> None:
    (
        session,
        scan_service,
        report_service,
        renderer,
    ) = create_mocks(
        monkeypatch,
    )

    scan_cli.run(
        application_id=1,
        repository_name="test-repo",
    )

    # scan_service.run.assert_called_once_with(
    #    1,
    #    "test-repo",
    #    "default",
    # )

    report_service.get_scan_summary.assert_called_once_with(
        42,
    )

    renderer.summary.assert_called_once_with(
        report_service.get_scan_summary.return_value,
    )

    session.close.assert_called_once_with()


def test_run_scan_creates_services_with_session(
    monkeypatch,
) -> None:
    (
        session,
        _,
        _,
        _,
    ) = create_mocks(
        monkeypatch,
    )

    scan_service_class = MagicMock()
    report_service_class = MagicMock()

    monkeypatch.setattr(
        "sentinel.cli.scan_cli.ScanService",
        scan_service_class,
    )

    monkeypatch.setattr(
        "sentinel.cli.scan_cli.ReportService",
        report_service_class,
    )

    scan_service_class.return_value.run.return_value.id = 42

    scan_service_class.return_value.run.return_value = (
        scan_service_class.return_value.run.return_value
    )

    report_service_class.return_value.get_scan_summary.return_value = (
        MagicMock()
    )

    scan_cli.run(
        application_id=1,
        repository_name="test-repo",
    )

    scan_service_class.assert_called_once_with(
        session,
    )

    report_service_class.assert_called_once_with(
        session,
    )


def test_run_scan_closes_session_when_value_error_occurs(
    monkeypatch,
) -> None:
    session = MagicMock()

    scan_service = MagicMock()

    scan_service.run.side_effect = ValueError(
        "Repository not found",
    )

    monkeypatch.setattr(
        "sentinel.cli.scan_cli.SessionLocal",
        lambda: session,
    )

    monkeypatch.setattr(
        "sentinel.cli.scan_cli.ScanService",
        lambda session: scan_service,
    )

    monkeypatch.setattr(
        "sentinel.cli.scan_cli.ReportService",
        MagicMock(),
    )

    result = runner.invoke(
        app,
        [
            "scan",
            "run",
            "1",
            "missing-repo",
        ],
    )
    assert result.exit_code == 1

    session.close.assert_called_once_with()


def test_run_scan_does_not_generate_report_when_scan_fails(
    monkeypatch,
) -> None:
    session = MagicMock()

    scan_service = MagicMock()

    scan_service.run.side_effect = ValueError(
        "Scan failed",
    )

    report_service = MagicMock()

    monkeypatch.setattr(
        "sentinel.cli.scan_cli.SessionLocal",
        lambda: session,
    )

    monkeypatch.setattr(
        "sentinel.cli.scan_cli.ScanService",
        lambda session: scan_service,
    )

    monkeypatch.setattr(
        "sentinel.cli.scan_cli.ReportService",
        lambda session: report_service,
    )

    result = runner.invoke(
        app,
        [
            "scan",
            "run",
            "1",
            "test-repo",
        ],
    )
    print(result.stdout)
    report_service.get_scan_summary.assert_not_called()

    session.close.assert_called_once_with()
