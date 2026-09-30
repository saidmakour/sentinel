from pathlib import Path
from unittest.mock import MagicMock
from unittest.mock import Mock
from unittest.mock import patch

from typer.testing import CliRunner

from sentinel.cli import report_cli
from sentinel.cli.app import app

runner = CliRunner()


# =============================================================================
# Tests pour la commande `latest`
# =============================================================================


def test_latest_success(
    monkeypatch,
) -> None:
    session = MagicMock()
    report_service = MagicMock()
    report = MagicMock()

    report_service.get_latest_summary.return_value = report

    renderer = MagicMock()

    monkeypatch.setattr(
        "sentinel.cli.report_cli.SessionLocal",
        lambda: session,
    )

    monkeypatch.setattr(
        "sentinel.cli.report_cli.ReportService",
        lambda session: report_service,
    )

    monkeypatch.setattr(
        "sentinel.cli.report_cli.ScanSummaryRenderer",
        renderer,
    )

    report_cli.latest()

    report_service.get_latest_summary.assert_called_once_with()

    renderer.summary.assert_called_once_with(
        report,
    )

    session.close.assert_called_once_with()


def test_latest_handles_value_error(
    monkeypatch,
) -> None:
    session = MagicMock()
    report_service = MagicMock()

    report_service.get_latest_summary.side_effect = ValueError(
        "No scans found",
    )

    monkeypatch.setattr(
        "sentinel.cli.report_cli.SessionLocal",
        lambda: session,
    )

    monkeypatch.setattr(
        "sentinel.cli.report_cli.ReportService",
        lambda session: report_service,
    )

    result = runner.invoke(
        app,
        [
            "report",
            "latest",
        ],
    )

    assert result.exit_code == 1
    assert "No scans found" in result.stdout

    report_service.get_latest_summary.assert_called_once_with()

    session.close.assert_called_once_with()


def test_latest_handles_generic_exception(
    monkeypatch,
) -> None:
    session = MagicMock()
    report_service = MagicMock()

    report_service.get_latest_summary.side_effect = RuntimeError(
        "Database error",
    )

    monkeypatch.setattr(
        "sentinel.cli.report_cli.SessionLocal",
        lambda: session,
    )

    monkeypatch.setattr(
        "sentinel.cli.report_cli.ReportService",
        lambda session: report_service,
    )

    with patch(
        "sentinel.cli.report_cli.logger",
    ) as mock_logger:
        result = runner.invoke(
            app,
            [
                "report",
                "latest",
            ],
        )

    assert result.exit_code == 1
    assert "Unable to display the latest scan report" in result.stdout

    mock_logger.exception.assert_called_once_with(
        "Failed to display latest scan report",
    )

    report_service.get_latest_summary.assert_called_once_with()

    session.close.assert_called_once_with()


# =============================================================================
# Tests pour la commande `show`
# =============================================================================


def test_show_handles_value_error(
    monkeypatch,
) -> None:
    session = MagicMock()
    scan_report_service = MagicMock()

    scan_report_service.get_report.side_effect = ValueError(
        "Scan not found",
    )

    monkeypatch.setattr(
        "sentinel.cli.report_cli.SessionLocal",
        lambda: session,
    )

    monkeypatch.setattr(
        "sentinel.cli.report_cli.ScanReportService",
        lambda session: scan_report_service,
    )

    result = runner.invoke(
        app,
        [
            "report",
            "show",
            "999",
        ],
    )

    assert result.exit_code == 1
    assert "Scan not found" in result.stdout

    scan_report_service.get_report.assert_called_once_with(
        999,
    )

    session.close.assert_called_once_with()


def test_show_success(
    monkeypatch,
) -> None:
    session = MagicMock()
    scan_report_service = MagicMock()
    report = MagicMock()

    scan_report_service.get_report.return_value = report

    renderer = MagicMock()

    monkeypatch.setattr(
        "sentinel.cli.report_cli.SessionLocal",
        lambda: session,
    )

    monkeypatch.setattr(
        "sentinel.cli.report_cli.ScanReportService",
        lambda session: scan_report_service,
    )

    monkeypatch.setattr(
        "sentinel.cli.report_cli.ScanReportRenderer",
        renderer,
    )

    report_cli.show(
        scan_id=42,
    )

    scan_report_service.get_report.assert_called_once_with(
        42,
    )

    renderer.summary.assert_called_once_with(
        report,
    )

    session.close.assert_called_once_with()


def test_show_handles_generic_exception(
    monkeypatch,
) -> None:
    session = MagicMock()
    scan_report_service = MagicMock()

    scan_report_service.get_report.side_effect = RuntimeError(
        "Database error",
    )

    monkeypatch.setattr(
        "sentinel.cli.report_cli.SessionLocal",
        lambda: session,
    )

    monkeypatch.setattr(
        "sentinel.cli.report_cli.ScanReportService",
        lambda session: scan_report_service,
    )

    with patch(
        "sentinel.cli.report_cli.logger",
    ) as mock_logger:
        result = runner.invoke(
            app,
            [
                "report",
                "show",
                "123",
            ],
        )

    assert result.exit_code == 1
    assert "Unable to display the scan report" in result.stdout

    mock_logger.exception.assert_called_once_with(
        "Failed to display scan report: scan_id=%s",
        123,
    )

    scan_report_service.get_report.assert_called_once_with(
        123,
    )

    session.close.assert_called_once_with()


# =============================================================================
# Tests pour la commande `history`
# =============================================================================


def test_history_handles_value_error(
    monkeypatch,
) -> None:
    session = MagicMock()
    report_service = MagicMock()

    report_service.get_history.side_effect = ValueError(
        "Unable to load history",
    )

    monkeypatch.setattr(
        "sentinel.cli.report_cli.SessionLocal",
        lambda: session,
    )

    monkeypatch.setattr(
        "sentinel.cli.report_cli.ReportService",
        lambda session: report_service,
    )

    result = runner.invoke(
        app,
        [
            "report",
            "history",
        ],
    )

    assert result.exit_code == 1
    assert "Unable to load history" in result.stdout

    report_service.get_history.assert_called_once_with()

    session.close.assert_called_once_with()


def test_history_success(
    monkeypatch,
) -> None:
    session = MagicMock()
    report_service = MagicMock()

    reports = [
        MagicMock(),
        MagicMock(),
    ]

    report_service.get_history.return_value = reports

    renderer = MagicMock()

    monkeypatch.setattr(
        "sentinel.cli.report_cli.SessionLocal",
        lambda: session,
    )

    monkeypatch.setattr(
        "sentinel.cli.report_cli.ReportService",
        lambda session: report_service,
    )

    monkeypatch.setattr(
        "sentinel.cli.report_cli.ScanSummaryRenderer",
        renderer,
    )

    report_cli.history()

    report_service.get_history.assert_called_once_with()

    renderer.history.assert_called_once_with(
        reports,
    )

    session.close.assert_called_once_with()


def test_history_handles_generic_exception(
    monkeypatch,
) -> None:
    session = MagicMock()
    report_service = MagicMock()

    report_service.get_history.side_effect = RuntimeError(
        "Database connection failed",
    )

    monkeypatch.setattr(
        "sentinel.cli.report_cli.SessionLocal",
        lambda: session,
    )

    monkeypatch.setattr(
        "sentinel.cli.report_cli.ReportService",
        lambda session: report_service,
    )

    with patch(
        "sentinel.cli.report_cli.logger",
    ) as mock_logger:
        result = runner.invoke(
            app,
            [
                "report",
                "history",
            ],
        )

    assert result.exit_code == 1
    assert "Unable to display scan history" in result.stdout

    mock_logger.exception.assert_called_once_with(
        "Failed to display scan history",
    )

    report_service.get_history.assert_called_once_with()

    session.close.assert_called_once_with()


# =============================================================================
# Tests pour la commande `export`
# =============================================================================


def test_export_report_success(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "scan-2.json"

    mock_export_service = Mock()
    mock_export_service.export.return_value = destination

    mock_session = Mock()

    with (
        patch(
            "sentinel.cli.report_cli.SessionLocal",
            return_value=mock_session,
        ),
        patch(
            "sentinel.cli.report_cli.ScanReportService",
            return_value=Mock(),
        ),
        patch(
            "sentinel.cli.report_cli.ReportExportService",
            return_value=mock_export_service,
        ),
    ):
        result = runner.invoke(
            app,
            [
                "report",
                "export",
                "--scan-id",
                "2",
                "--format",
                "json",
            ],
        )

    assert result.exit_code == 0

    assert result.stdout == (f"Rapport exporté : {destination}\n")

    mock_export_service.export.assert_called_once_with(
        scan_id=2,
        format="json",
    )

    mock_session.close.assert_called_once()


def test_export_handles_value_error(
    monkeypatch,
    tmp_path: Path,
) -> None:
    mock_session = Mock()
    mock_scan_report_service = Mock()
    mock_export_service = Mock()

    mock_export_service.export.side_effect = ValueError(
        "Invalid format specified",
    )

    monkeypatch.setattr(
        "sentinel.cli.report_cli.SessionLocal",
        lambda: mock_session,
    )

    monkeypatch.setattr(
        "sentinel.cli.report_cli.ScanReportService",
        lambda session: mock_scan_report_service,
    )

    with patch(
        "sentinel.cli.report_cli.ReportExportService",
        return_value=mock_export_service,
    ):
        result = runner.invoke(
            app,
            [
                "report",
                "export",
                "--scan-id",
                "5",
                "--format",
                "pdf",
            ],
        )

    assert result.exit_code == 1
    assert "Invalid format specified" in result.stdout

    mock_export_service.export.assert_called_once_with(
        scan_id=5,
        format="pdf",
    )

    mock_session.close.assert_called_once()


def test_export_handles_generic_exception(
    monkeypatch,
    tmp_path: Path,
) -> None:
    mock_session = Mock()
    mock_scan_report_service = Mock()
    mock_export_service = Mock()

    mock_export_service.export.side_effect = RuntimeError(
        "File write error",
    )

    monkeypatch.setattr(
        "sentinel.cli.report_cli.SessionLocal",
        lambda: mock_session,
    )

    monkeypatch.setattr(
        "sentinel.cli.report_cli.ScanReportService",
        lambda session: mock_scan_report_service,
    )

    with (
        patch(
            "sentinel.cli.report_cli.ReportExportService",
            return_value=mock_export_service,
        ),
        patch(
            "sentinel.cli.report_cli.logger",
        ) as mock_logger,
    ):
        result = runner.invoke(
            app,
            [
                "report",
                "export",
                "--scan-id",
                "10",
                "--format",
                "csv",
            ],
        )

    assert result.exit_code == 1
    assert "Unable to export the scan report" in result.stdout

    mock_logger.exception.assert_called_once_with(
        "Failed to export scan report: scan_id=%s format=%s",
        10,
        "csv",
    )

    mock_export_service.export.assert_called_once_with(
        scan_id=10,
        format="csv",
    )

    mock_session.close.assert_called_once()


def test_export_missing_required_options(
    monkeypatch,
) -> None:
    """Test que l'export échoue si les options requises sont manquantes."""
    mock_session = Mock()

    monkeypatch.setattr(
        "sentinel.cli.report_cli.SessionLocal",
        lambda: mock_session,
    )

    # Sans --scan-id et --format, Typer retourne une erreur d'usage (exit code 2)
    result = runner.invoke(
        app,
        [
            "report",
            "export",
        ],
    )

    # On vérifie juste que c'est une erreur d'usage
    assert result.exit_code == 2


# =============================================================================
# Tests additionnels pour la couverture complète
# =============================================================================


def test_report_cli_help() -> None:
    """Test que le help du groupe report fonctionne."""
    result = runner.invoke(
        app,
        [
            "report",
            "--help",
        ],
    )

    assert result.exit_code == 0
    assert "Consulter les rapports de scan" in result.stdout
    assert "latest" in result.stdout
    assert "show" in result.stdout
    assert "history" in result.stdout
    assert "export" in result.stdout


def test_report_cli_subcommand_help() -> None:
    """Test que le help des sous-commandes fonctionne."""
    for subcommand in ["latest", "show", "history", "export"]:
        result = runner.invoke(
            app,
            [
                "report",
                subcommand,
                "--help",
            ],
        )

        assert result.exit_code == 0
        assert "Usage:" in result.stdout


def test_show_with_different_scan_ids(
    monkeypatch,
) -> None:
    """Test show avec différents IDs de scan."""
    session = MagicMock()
    scan_report_service = MagicMock()
    report = MagicMock()

    scan_report_service.get_report.return_value = report
    renderer = MagicMock()

    monkeypatch.setattr(
        "sentinel.cli.report_cli.SessionLocal",
        lambda: session,
    )

    monkeypatch.setattr(
        "sentinel.cli.report_cli.ScanReportService",
        lambda session: scan_report_service,
    )

    monkeypatch.setattr(
        "sentinel.cli.report_cli.ScanReportRenderer",
        renderer,
    )

    for scan_id in [1, 100, 9999]:
        session.reset_mock()
        scan_report_service.reset_mock()
        renderer.reset_mock()

        report_cli.show(scan_id=scan_id)

        scan_report_service.get_report.assert_called_once_with(scan_id)
        renderer.summary.assert_called_once_with(report)
        session.close.assert_called_once()


def test_export_with_different_formats(
    tmp_path: Path,
) -> None:
    """Test export avec différents formats."""
    mock_session = Mock()
    mock_scan_report_service = Mock()
    mock_export_service = Mock()

    destination = tmp_path / "report.json"
    mock_export_service.export.return_value = destination

    with (
        patch(
            "sentinel.cli.report_cli.SessionLocal",
            return_value=mock_session,
        ),
        patch(
            "sentinel.cli.report_cli.ScanReportService",
            return_value=mock_scan_report_service,
        ),
        patch(
            "sentinel.cli.report_cli.ReportExportService",
            return_value=mock_export_service,
        ),
    ):
        for fmt in ["json", "csv", "html"]:
            mock_session.reset_mock()
            mock_export_service.reset_mock()

            result = runner.invoke(
                app,
                [
                    "report",
                    "export",
                    "--scan-id",
                    "1",
                    "--format",
                    fmt,
                ],
            )

            assert result.exit_code == 0
            mock_export_service.export.assert_called_once_with(
                scan_id=1,
                format=fmt,
            )
            mock_session.close.assert_called_once()
