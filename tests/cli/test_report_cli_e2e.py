from pathlib import Path

import pytest
from typer.testing import CliRunner

from sentinel.cli.app import app

runner = CliRunner()


@pytest.mark.skip(reason="OK")
def test_report_show_e2e(
    db_session,
) -> None:
    result = runner.invoke(
        app,
        [
            "report",
            "show",
            "1",
        ],
    )

    assert result.exit_code == 0

    output = result.stdout

    assert "Sentinel Scan Report" in output
    assert "Scan ID" in output
    assert "3" in output
    assert "Repository ID" in output
    assert "Scan Status" in output
    assert "Security Status" in output
    assert "Risk" in output
    assert "Dependency Security" in output


@pytest.mark.skip(reason="OK")
def test_report_latest_e2e(
    db_session,
) -> None:
    result = runner.invoke(
        app,
        [
            "report",
            "latest",
        ],
    )

    assert result.exit_code == 0

    output = result.stdout

    assert "Sentinel Scan Report" in output
    assert "Scan ID" in output
    assert "Scan Status" in output


@pytest.mark.skip(reason="OK")
def test_report_history_e2e(
    db_session,
) -> None:
    result = runner.invoke(
        app,
        [
            "report",
            "history",
        ],
    )

    assert result.exit_code == 0

    output = result.stdout

    print("STDOUT:")
    print(repr(result.stdout))

    print("OUTPUT:")
    print(repr(result.output))

    print("EXCEPTION:")
    print(result.exception)
    assert "Scan History" in output
    assert "Scan ID" in output
    assert "Status" in output
    assert "Dependenc" in output
    assert "Findings" in output
    assert "Duration" in output
    assert "Source" in output
    assert "Reference" in output

    assert "SUCCESS" in output
    assert "FAILED" in output


@pytest.mark.skip(reason="OK")
def test_report_export_json_e2e(
    db_session,
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "sentinel.services.report_export_service.settings.report_path",
        str(tmp_path),
    )

    result = runner.invoke(
        app,
        [
            "report",
            "export",
            "--scan-id",
            "3",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert "Rapport exporté" in result.stdout

    destination = tmp_path / "scan-3.json"

    assert destination.exists()

    content = destination.read_text(
        encoding="utf-8",
    )

    assert '"scan"' in content
    assert '"security_status"' in content
    assert '"dependency_security"' in content
    assert '"findings"' in content


@pytest.mark.skip(reason="OK")
def test_report_export_markdown_e2e(
    db_session,
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "sentinel.services.report_export_service.settings.report_path",
        str(tmp_path),
    )

    result = runner.invoke(
        app,
        [
            "report",
            "export",
            "--scan-id",
            "3",
            "--format",
            "markdown",
        ],
    )

    assert result.exit_code == 0
    assert "Rapport exporté" in result.stdout

    destination = tmp_path / "scan-3.markdown"

    assert destination.exists()

    content = destination.read_text(
        encoding="utf-8",
    )

    assert "# Sentinel Vulnerability Report" in content
    assert "Security Status" in content
    assert "Dependency" in content


@pytest.mark.skip(reason="OK")
def test_report_export_html_e2e(
    db_session,
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "sentinel.services.report_export_service.settings.report_path",
        str(tmp_path),
    )

    result = runner.invoke(
        app,
        [
            "report",
            "export",
            "--scan-id",
            "3",
            "--format",
            "html",
        ],
    )

    assert result.exit_code == 0
    assert "Rapport exporté" in result.stdout

    destination = tmp_path / "scan-3.html"

    assert destination.exists()

    content = destination.read_text(
        encoding="utf-8",
    )

    assert "<!DOCTYPE html>" in content
    assert "Sentinel Vulnerability Report" in content
    assert "Security Status" in content


@pytest.mark.skip(reason="OK")
def test_report_export_sarif_e2e(
    db_session,
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "sentinel.services.report_export_service.settings.report_path",
        str(tmp_path),
    )

    result = runner.invoke(
        app,
        [
            "report",
            "export",
            "--scan-id",
            "3",
            "--format",
            "sarif",
        ],
    )

    assert result.exit_code == 0
    assert "Rapport exporté" in result.stdout

    destination = tmp_path / "scan-3.sarif"

    assert destination.exists()

    content = destination.read_text(
        encoding="utf-8",
    )

    assert '"version": "2.1.0"' in content
    assert '"runs"' in content
    assert '"Sentinel"' in content
    assert '"results"' in content
