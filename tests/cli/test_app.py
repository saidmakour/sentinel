from typer.testing import CliRunner

from sentinel.cli.app import app

runner = CliRunner()


def test_root_app_has_commands():
    commands = app.registered_commands
    assert commands is not None


def test_root_help():
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Interface en ligne de commande Sentinel" in result.stdout
    assert "sys" in result.stdout
    assert "app" in result.stdout
    assert "repo" in result.stdout
    assert "scan" in result.stdout
    assert "report" in result.stdout


def test_sys_help():
    result = runner.invoke(app, ["sys", "--help"])

    assert result.exit_code == 0
    assert "commandes système" in result.stdout.lower()
    assert "version" in result.stdout
    assert "init" in result.stdout
    assert "doctor" in result.stdout


def test_app_help():
    result = runner.invoke(app, ["app", "--help"])

    assert result.exit_code == 0
    assert "applications" in result.stdout.lower()
    assert "create" in result.stdout
    assert "list" in result.stdout
    assert "show" in result.stdout
    assert "delete" in result.stdout


def test_repo_help():
    result = runner.invoke(app, ["repo", "--help"])

    assert result.exit_code == 0
    assert (
        "dépôts" in result.stdout.lower() or "depots" in result.stdout.lower()
    )
    assert "list" in result.stdout
    assert "add" in result.stdout
    assert "delete" in result.stdout


def test_scan_help():
    result = runner.invoke(app, ["scan", "--help"])

    assert result.exit_code == 0
    assert "scan" in result.stdout.lower()
    assert "run" in result.stdout


def test_report_help():
    result = runner.invoke(app, ["report", "--help"])

    assert result.exit_code == 0
    assert "rapport" in result.stdout.lower()
    assert "latest" in result.stdout
    assert "show" in result.stdout
    assert "history" in result.stdout
