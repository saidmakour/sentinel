from unittest.mock import MagicMock
from unittest.mock import patch

from typer.testing import CliRunner

from sentinel.cli.application_cli import app_cli

runner = CliRunner()


def test_create_application_success():
    fake_app = MagicMock()
    fake_app.name = "App1"

    with (
        patch(
            "sentinel.cli.application_cli.SessionLocal"
        ) as mock_session_local,
        patch(
            "sentinel.cli.application_cli.ApplicationService"
        ) as mock_service_cls,
    ):
        session = MagicMock()
        mock_session_local.return_value = session

        service = MagicMock()
        service.create.return_value = fake_app
        mock_service_cls.return_value = service

        result = runner.invoke(app_cli, ["create", "App1"])

        assert result.exit_code == 0, result.stdout
        assert "Created application: App1" in result.stdout
        service.create.assert_called_once_with(
            name="App1",
            description="",
            owner="",
            criticality=3,
        )
        session.close.assert_called_once()


def test_create_application_value_error():
    with (
        patch(
            "sentinel.cli.application_cli.SessionLocal"
        ) as mock_session_local,
        patch(
            "sentinel.cli.application_cli.ApplicationService"
        ) as mock_service_cls,
    ):
        session = MagicMock()
        mock_session_local.return_value = session

        service = MagicMock()
        service.create.side_effect = ValueError("Application already exists")
        mock_service_cls.return_value = service

        result = runner.invoke(
            app_cli,
            ["create", "App1"],
        )

        assert result.exit_code == 1
        assert "Application already exists" in result.stdout
        service.create.assert_called_once_with(
            name="App1",
            description="",
            owner="",
            criticality=3,
        )
        session.close.assert_called_once()


def test_list_applications_empty():
    with (
        patch(
            "sentinel.cli.application_cli.SessionLocal"
        ) as mock_session_local,
        patch(
            "sentinel.cli.application_cli.ApplicationService"
        ) as mock_service_cls,
    ):
        session = MagicMock()
        mock_session_local.return_value = session

        service = MagicMock()
        service.list_all.return_value = []
        mock_service_cls.return_value = service

        result = runner.invoke(
            app_cli,
            ["list"],
        )

        assert result.exit_code == 0, result.stdout
        assert "Applications:" in result.stdout
        service.list_all.assert_called_once_with()
        session.close.assert_called_once()


def test_list_applications():
    app1 = MagicMock()
    app1.id = 1
    app1.name = "App1"
    app1.criticality = 3

    app2 = MagicMock()
    app2.id = 2
    app2.name = "App2"
    app2.criticality = 2

    with (
        patch(
            "sentinel.cli.application_cli.SessionLocal"
        ) as mock_session_local,
        patch(
            "sentinel.cli.application_cli.ApplicationService"
        ) as mock_service_cls,
    ):
        session = MagicMock()
        mock_session_local.return_value = session

        service = MagicMock()
        service.list_all.return_value = [app1, app2]
        mock_service_cls.return_value = service

        result = runner.invoke(
            app_cli,
            ["list"],
        )

        assert result.exit_code == 0, result.stdout
        assert "Applications:" in result.stdout
        assert "- 1: App1 (criticality=3)" in result.stdout
        assert "- 2: App2 (criticality=2)" in result.stdout

        service.list_all.assert_called_once_with()
        session.close.assert_called_once()


def test_show_application():
    application = MagicMock()
    application.name = "App1"
    application.description = "Application description"
    application.owner = "John Doe"
    application.criticality = 3

    with (
        patch(
            "sentinel.cli.application_cli.SessionLocal"
        ) as mock_session_local,
        patch(
            "sentinel.cli.application_cli.ApplicationService"
        ) as mock_service_cls,
    ):
        session = MagicMock()
        mock_session_local.return_value = session

        service = MagicMock()
        service.get_by_name.return_value = application
        mock_service_cls.return_value = service

        result = runner.invoke(
            app_cli,
            ["show", "App1"],
        )

        assert result.exit_code == 0, result.stdout
        assert "App1" in result.stdout
        assert "Description: Application description" in result.stdout
        assert "Owner: John Doe" in result.stdout
        assert "Criticality: 3" in result.stdout

        service.get_by_name.assert_called_once_with("App1")
        session.close.assert_called_once()


def test_show_application_not_found():
    with (
        patch(
            "sentinel.cli.application_cli.SessionLocal"
        ) as mock_session_local,
        patch(
            "sentinel.cli.application_cli.ApplicationService"
        ) as mock_service_cls,
    ):
        session = MagicMock()
        mock_session_local.return_value = session

        service = MagicMock()
        service.get_by_name.return_value = None
        mock_service_cls.return_value = service

        result = runner.invoke(
            app_cli,
            ["show", "Unknown"],
        )

        assert result.exit_code == 0, result.stdout
        assert "Application not found" in result.stdout

        service.get_by_name.assert_called_once_with("Unknown")
        session.close.assert_called_once()


def test_delete_application_success():
    with (
        patch(
            "sentinel.cli.application_cli.SessionLocal"
        ) as mock_session_local,
        patch(
            "sentinel.cli.application_cli.ApplicationService"
        ) as mock_service_cls,
    ):
        session = MagicMock()
        mock_session_local.return_value = session

        service = MagicMock()
        mock_service_cls.return_value = service

        result = runner.invoke(
            app_cli,
            ["delete", "App1"],
        )

        assert result.exit_code == 0, result.stdout
        assert "Deleted application: App1" in result.stdout

        service.delete.assert_called_once_with("App1")
        session.close.assert_called_once()


def test_delete_application_value_error():
    with (
        patch(
            "sentinel.cli.application_cli.SessionLocal"
        ) as mock_session_local,
        patch(
            "sentinel.cli.application_cli.ApplicationService"
        ) as mock_service_cls,
    ):
        session = MagicMock()
        mock_session_local.return_value = session

        service = MagicMock()
        service.delete.side_effect = ValueError("Application not found")
        mock_service_cls.return_value = service

        result = runner.invoke(
            app_cli,
            ["delete", "Unknown"],
        )

        assert result.exit_code == 1
        assert "Application not found" in result.stdout

        service.delete.assert_called_once_with("Unknown")
        session.close.assert_called_once()
