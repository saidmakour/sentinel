import typer

from sentinel.database.session import SessionLocal
from sentinel.enums.criticality import Criticality
from sentinel.log import get_logger
from sentinel.services.application_service import ApplicationService

logger = get_logger(__name__)

app_cli = typer.Typer(
    help="Gérer les applications enregistrées dans Sentinel.",
)


@app_cli.command(
    "create",
    help="Créer une nouvelle application.",
)
def create(
    name: str,
    description: str = "",
    owner: str = "",
    criticality: Criticality = Criticality.HIGH,
) -> None:
    session = SessionLocal()

    try:
        service = ApplicationService(
            session,
        )

        app = service.create(
            name=name,
            description=description,
            owner=owner,
            criticality=criticality,
        )

        typer.secho(
            f"Created application: {app.name}",
            fg=typer.colors.GREEN,
        )

    except ValueError as exc:
        typer.secho(
            str(exc),
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    except Exception:
        logger.exception(
            "Failed to create application: name=%s",
            name,
        )

        typer.secho(
            "Failed to create application. Check the logs for more details.",
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    finally:
        session.close()


@app_cli.command(
    "list",
    help="Lister toutes les applications.",
)
def list_apps() -> None:
    session = SessionLocal()

    try:
        service = ApplicationService(
            session,
        )

        apps = service.list_all()

        typer.echo(
            "\nApplications:\n",
        )

        for app in apps:
            typer.echo(
                f"- {app.id}: {app.name} (criticality={app.criticality})",
            )

    except Exception:
        logger.exception(
            "Failed to list applications",
        )

        typer.secho(
            "Failed to list applications. Check the logs for more details.",
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    finally:
        session.close()


@app_cli.command(
    "show",
    help="Afficher le détail d'une application.",
)
def show(
    name: str,
) -> None:
    session = SessionLocal()

    try:
        service = ApplicationService(
            session,
        )

        app = service.get_by_name(
            name,
        )

        if not app:
            typer.secho(
                "Application not found",
                fg=typer.colors.RED,
            )
            return

        typer.echo(
            f"\n{app.name}",
        )
        typer.echo(
            f"Description: {app.description}",
        )
        typer.echo(
            f"Owner: {app.owner}",
        )
        typer.echo(
            f"Criticality: {app.criticality}",
        )

    except ValueError as exc:
        typer.secho(
            str(exc),
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    except Exception:
        logger.exception(
            "Failed to show application: name=%s",
            name,
        )

        typer.secho(
            "Failed to show application. Check the logs for more details.",
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    finally:
        session.close()


@app_cli.command(
    "delete",
    help="Supprimer une application.",
)
def delete(
    name: str,
) -> None:
    session = SessionLocal()

    try:
        service = ApplicationService(
            session,
        )

        service.delete(
            name,
        )

        typer.secho(
            f"Deleted application: {name}",
            fg=typer.colors.GREEN,
        )

    except ValueError as exc:
        typer.secho(
            str(exc),
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    except Exception:
        logger.exception(
            "Failed to delete application: name=%s",
            name,
        )

        typer.secho(
            "Failed to delete application. Check the logs for more details.",
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    finally:
        session.close()
