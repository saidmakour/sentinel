from pathlib import Path

import typer

from sentinel.database.session import SessionLocal
from sentinel.enums.git_auth_method import GitAuthMethod
from sentinel.log import get_logger
from sentinel.services.repository_service import RepositoryService

logger = get_logger(__name__)

repo_cli = typer.Typer(
    help="Gérer les dépôts de code associés aux applications.",
)


@repo_cli.command(
    "list_all",
    help="Lister tout dépôts",
)
def list_all_repos() -> None:
    session = SessionLocal()

    try:
        service = RepositoryService(session)
        repos = service.list_all()

        if not repos:
            typer.echo(
                "No repositories found.",
            )
            return

        typer.echo(
            "\nRepositories:\n",
        )

        for repository in repos:
            typer.echo(
                f"id: {repository.id} "
                f"- name: {repository.name} "
                f"({repository.local_path}) "
                f"(url={repository.remote_url})"
                f"[{repository.language}/"
                f"{repository.package_manager}] "
                f"branch={repository.default_branch}",
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
        logger.exception("Failed to list repositories")

        typer.secho(
            "Failed to list repositories. Check the logs for more details.",
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    finally:
        session.close()


@repo_cli.command(
    "list",
    help="Lister les dépôts d'une application.",
)
def list_repos(
    application_id: int,
) -> None:
    session = SessionLocal()

    try:
        service = RepositoryService(session)
        repos = service.list_by_application(
            application_id,
        )

        if not repos:
            typer.echo(
                "No repositories found.",
            )
            return

        typer.echo(
            "\nRepositories:\n",
        )

        for repository in repos:
            typer.echo(
                f"- {repository.name} "
                f"({repository.local_path}) "
                f"(url={repository.remote_url})"
                f"[{repository.language}/"
                f"{repository.package_manager}] "
                f"branch={repository.default_branch}",
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
            "Failed to list repositories: application_id=%s",
            application_id,
        )

        typer.secho(
            "Failed to list repositories. Check the logs for more details.",
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    finally:
        session.close()


@repo_cli.command(
    "add",
    help="Ajouter un dépôt à une application.",
)
def add_repo(
    application_id: int,
    name: str,
    path: Path,
    remote_url: str | None = typer.Option(
        None,
        "--remote-url",
        help="URL du dépôt Git distant. Si absente, le dépôt est considéré comme local.",
    ),
    branch: str = typer.Option(  # pyright: ignore[reportUnknownMemberType]
        "main",
        "--branch",
        help="Branche Git par défaut du dépôt.",
    ),
    language: str = typer.Option(  # pyright: ignore[reportUnknownMemberType]
        "python",
        "--language",
        help="Langage principal du dépôt.",
    ),
    package_manager: str = typer.Option(  # pyright: ignore[reportUnknownMemberType]
        "pip",
        "--package-manager",
        help="Gestionnaire de paquets utilisé par le dépôt.",
    ),
    auth_method: GitAuthMethod = typer.Option(  # noqa:B008 # pyright: ignore[reportUnknownMemberType]
        GitAuthMethod.NONE,
        "--auth-method",
        help="Méthode d'authentification Git.",
    ),
) -> None:
    session = SessionLocal()

    try:
        service = RepositoryService(session)

        repo = service.create(
            application_id=application_id,
            name=name,
            local_path=str(path),
            remote_url=remote_url,
            default_branch=branch,
            language=language,
            package_manager=package_manager,
            auth_method=auth_method,
        )

        typer.secho(
            f"Repository created: {repo.name}",
            fg=typer.colors.GREEN,
        )

        typer.echo(
            f"  Branch          : {repo.default_branch}",
        )
        typer.echo(
            f"  Language        : {repo.language}",
        )
        typer.echo(
            f"  Package manager : {repo.package_manager}",
        )
        typer.echo(
            f"  Auth method     : {repo.auth_method}",
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
            "Failed to create repository: application_id=%s name=%s",
            application_id,
            name,
        )

        typer.secho(
            "Failed to create repository. Check the logs for more details.",
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    finally:
        session.close()


@repo_cli.command(
    "delete",
    help="Supprimer un dépôt d'une application.",
)
def delete_repo(
    repo_id: int,
) -> None:
    session = SessionLocal()

    try:
        service = RepositoryService(session)

        service.delete(
            repo_id,
        )

        typer.secho(
            f"Deleted repository: {repo_id}",
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
            "Failed to delete repository: repo_id=%s",
            repo_id,
        )

        typer.secho(
            "Failed to delete repository. Check the logs for more details.",
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    finally:
        session.close()
