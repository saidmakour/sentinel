import typer

from sentinel.config.settings import settings
from sentinel.database.init_db import create_database
from sentinel.doctor.service import DoctorService
from sentinel.enums.doctor_status import DoctorStatus
from sentinel.log import get_logger
from sentinel.services.directory_service import DirectoryService

logger = get_logger(__name__)

sys_cli = typer.Typer(
    help="Exécuter les commandes système et de diagnostic de Sentinel.",
)


@sys_cli.command(
    "version",
    help="Afficher la version courante de Sentinel.",
)
def version() -> None:
    typer.secho(
        f"{settings.app_name} {settings.app_version}",
        fg=typer.colors.MAGENTA,
        bold=True,
    )


@sys_cli.command(
    "init",
    help="Initialiser l'espace de travail Sentinel.",
)
def init() -> None:
    try:
        DirectoryService.ensure_structure()
        create_database()

        typer.secho(
            "Workspace initialized.",
            fg=typer.colors.GREEN,
        )

    except Exception:
        logger.exception(
            "Workspace initialization failed",
        )

        typer.secho(
            "Workspace initialization failed. "
            "Check the logs for more details.",
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None


@sys_cli.command(
    "doctor",
    help="Vérifier l'installation locale et les chemins requis.",
)
def doctor() -> None:
    service = DoctorService()

    try:
        report = service.run()

        typer.echo()

        for check in report.checks:
            if check.status == DoctorStatus.PASS:
                typer.secho(
                    f"✔ {check.name}: {check.message}",
                    fg=typer.colors.GREEN,
                )

            elif check.status == DoctorStatus.WARNING:
                typer.secho(
                    f"⚠ {check.name}: {check.message}",
                    fg=typer.colors.YELLOW,
                )

            else:
                typer.secho(
                    f"✘ {check.name}: {check.message}",
                    fg=typer.colors.RED,
                )

        typer.echo()

        typer.echo(
            f"Total: {report.total} | "
            f"Passed: {report.passed} | "
            f"Warnings: {report.warnings} | "
            f"Failed: {report.failed}",
        )

        if report.failed > 0:
            raise typer.Exit(
                code=1,
            )

    except typer.Exit:
        raise

    except Exception:
        logger.exception(
            "Doctor command failed",
        )

        typer.secho(
            "Doctor check failed. Check the logs for more details.",
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None
