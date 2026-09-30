import typer

from sentinel.cli.application_cli import app_cli
from sentinel.cli.report_cli import report_cli
from sentinel.cli.repository_cli import repo_cli
from sentinel.cli.scan_cli import scan_cli
from sentinel.cli.system_cli import sys_cli
from sentinel.cli.user_cli import user_cli

app = typer.Typer(
    help=(
        "Interface en ligne de commande Sentinel pour gérer les applications, "
        "les dépôts, les scans et les rapports."
    )
)

app.add_typer(sys_cli, name="sys")
app.add_typer(app_cli, name="app")
app.add_typer(repo_cli, name="repo")
app.add_typer(scan_cli, name="scan")
app.add_typer(report_cli, name="report")
app.add_typer(user_cli, name="user")
