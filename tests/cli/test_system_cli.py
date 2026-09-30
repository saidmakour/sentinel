from unittest.mock import patch

from typer.testing import CliRunner

from sentinel.cli.system_cli import sys_cli
from sentinel.dto.doctor_check import DoctorCheck
from sentinel.dto.doctor_report import DoctorReport
from sentinel.enums.doctor_status import DoctorStatus

runner = CliRunner()


def test_version():
    with patch("sentinel.cli.system_cli.settings") as mock_settings:
        mock_settings.app_name = "Sentinel"
        mock_settings.app_version = "1.0.0"

        result = runner.invoke(sys_cli, ["version"])

        assert result.exit_code == 0
        assert "Sentinel 1.0.0" in result.stdout


def test_init():
    with (
        patch("sentinel.cli.system_cli.DirectoryService") as mock_dir_service,
        patch("sentinel.cli.system_cli.create_database") as mock_create_db,
    ):
        result = runner.invoke(sys_cli, ["init"])

        assert result.exit_code == 0
        assert "Workspace initialized." in result.stdout
        mock_dir_service.ensure_structure.assert_called_once()
        mock_create_db.assert_called_once()


def test_doctor_success_when_all_checks_pass() -> None:
    report = DoctorReport(
        checks=[
            DoctorCheck(
                name="database",
                status=DoctorStatus.PASS,
                message="Database available",
            ),
            DoctorCheck(
                name="directory",
                status=DoctorStatus.PASS,
                message="Directory available",
            ),
        ],
    )

    with patch(
        "sentinel.cli.system_cli.DoctorService",
    ) as mock_service_cls:
        mock_service = mock_service_cls.return_value
        mock_service.run.return_value = report

        result = runner.invoke(
            sys_cli,
            ["doctor"],
        )

    assert result.exit_code == 0

    assert "✔ database: Database available" in result.stdout
    assert "✔ directory: Directory available" in result.stdout
    assert "Total: 2" in result.stdout
    assert "Passed: 2" in result.stdout
    assert "Warnings: 0" in result.stdout
    assert "Failed: 0" in result.stdout

    mock_service.run.assert_called_once_with()


def test_doctor_returns_exit_code_1_when_check_fails() -> None:
    report = DoctorReport(
        checks=[
            DoctorCheck(
                name="database",
                status=DoctorStatus.PASS,
                message="Database available",
            ),
            DoctorCheck(
                name="directory",
                status=DoctorStatus.FAIL,
                message="Directory not found",
            ),
        ],
    )

    with patch(
        "sentinel.cli.system_cli.DoctorService",
    ) as mock_service_cls:
        mock_service = mock_service_cls.return_value
        mock_service.run.return_value = report

        result = runner.invoke(
            sys_cli,
            ["doctor"],
        )

    assert result.exit_code == 1

    assert "✔ database: Database available" in result.stdout
    assert "✘ directory: Directory not found" in result.stdout
    assert "Total: 2" in result.stdout
    assert "Passed: 1" in result.stdout
    assert "Warnings: 0" in result.stdout
    assert "Failed: 1" in result.stdout

    mock_service.run.assert_called_once_with()


def test_doctor_returns_exit_code_0_when_only_warnings() -> None:
    report = DoctorReport(
        checks=[
            DoctorCheck(
                name="provider.NVD",
                status=DoctorStatus.WARNING,
                message="Provider unavailable",
            ),
        ],
    )

    with patch(
        "sentinel.cli.system_cli.DoctorService",
    ) as mock_service_cls:
        mock_service = mock_service_cls.return_value
        mock_service.run.return_value = report

        result = runner.invoke(
            sys_cli,
            ["doctor"],
        )

    assert result.exit_code == 0
    assert "⚠ provider.NVD: Provider unavailable" in result.stdout
    assert "Warnings: 1" in result.stdout
    assert "Failed: 0" in result.stdout
