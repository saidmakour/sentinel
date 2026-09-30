import typer

from sentinel.database.session import SessionLocal
from sentinel.exceptions.auth import LastAdminError
from sentinel.exceptions.auth import UserAlreadyExistsError
from sentinel.exceptions.auth import UserNotFoundError
from sentinel.log import get_logger
from sentinel.services.auth_service import AuthService

logger = get_logger(__name__)

user_cli = typer.Typer(
    help="Gérer les utilisateurs de Sentinel.",
)


@user_cli.command(
    "create",
    help="Créer un nouvel utilisateur.",
)
def create_user(
    username: str,
    password: str = typer.Option(
        ...,
        "--password",
        help="Mot de passe de l'utilisateur.",
        prompt=True,
        hide_input=True,
        confirmation_prompt=True,
    ),
    admin: bool = typer.Option(
        False,
        "--admin",
        help="Créer l'utilisateur avec les droits administrateur.",
    ),
) -> None:
    session = SessionLocal()

    try:
        service = AuthService(session)

        user = service.create_user(
            username=username,
            password=password,
            is_admin=admin,
        )

        typer.secho(
            f"Utilisateur créé : {user.username}",
            fg=typer.colors.GREEN,
        )

        typer.echo(
            f"  ID     : {user.id}",
        )
        typer.echo(
            f"  Admin  : {user.is_admin}",
        )
        typer.echo(
            f"  Actif  : {user.is_active}",
        )

    except UserAlreadyExistsError as exc:
        typer.secho(
            str(exc),
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    except Exception:
        session.rollback()

        logger.exception(
            "Failed to create user: username=%s",
            username,
        )

        typer.secho(
            "Impossible de créer l'utilisateur. "
            "Consultez les logs pour plus de détails.",
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    finally:
        session.close()


@user_cli.command(
    "list",
    help="Lister les utilisateurs.",
)
def list_users() -> None:
    session = SessionLocal()

    try:
        service = AuthService(session)

        users = service.list_users()

        if not users:
            typer.echo(
                "Aucun utilisateur trouvé.",
            )
            return

        typer.echo(
            "\nUtilisateurs :\n",
        )

        for user in users:
            role = "ADMIN" if user.is_admin else "USER"

            status = "ACTIF" if user.is_active else "INACTIF"

            typer.echo(
                f"- {user.id}: {user.username} [{role}] [{status}]",
            )

    except Exception:
        logger.exception(
            "Failed to list users",
        )

        typer.secho(
            "Impossible de lister les utilisateurs. "
            "Consultez les logs pour plus de détails.",
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    finally:
        session.close()


@user_cli.command(
    "password",
    help="Modifier le mot de passe d'un utilisateur.",
)
def change_password(
    username: str,
    password: str = typer.Option(
        ...,
        "--password",
        help="Nouveau mot de passe.",
        prompt=True,
        hide_input=True,
        confirmation_prompt=True,
    ),
) -> None:
    session = SessionLocal()

    try:
        service = AuthService(session)

        service.change_password(
            username=username,
            password=password,
        )

        typer.secho(
            f"Mot de passe modifié pour : {username}",
            fg=typer.colors.GREEN,
        )

    except UserNotFoundError as exc:
        typer.secho(
            str(exc),
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    except Exception:
        session.rollback()

        logger.exception(
            "Failed to change password: username=%s",
            username,
        )

        typer.secho(
            "Impossible de modifier le mot de passe. "
            "Consultez les logs pour plus de détails.",
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    finally:
        session.close()


@user_cli.command(
    "promote",
    help="Promouvoir un utilisateur en administrateur.",
)
def promote_user(
    username: str,
) -> None:
    session = SessionLocal()

    try:
        service = AuthService(session)

        service.promote_user(
            username,
        )

        typer.secho(
            f"Utilisateur promu administrateur : {username}",
            fg=typer.colors.GREEN,
        )

    except UserNotFoundError as exc:
        typer.secho(
            str(exc),
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    except Exception:
        session.rollback()

        logger.exception(
            "Failed to promote user: username=%s",
            username,
        )

        typer.secho(
            "Impossible de promouvoir l'utilisateur. "
            "Consultez les logs pour plus de détails.",
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    finally:
        session.close()


@user_cli.command(
    "demote",
    help="Retirer les droits administrateur d'un utilisateur.",
)
def demote_user(
    username: str,
) -> None:
    session = SessionLocal()

    try:
        service = AuthService(session)

        service.demote_user(
            username,
        )

        typer.secho(
            f"Droits administrateur retirés : {username}",
            fg=typer.colors.GREEN,
        )

    except (
        UserNotFoundError,
        LastAdminError,
    ) as exc:
        typer.secho(
            str(exc),
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    except Exception:
        session.rollback()

        logger.exception(
            "Failed to demote user: username=%s",
            username,
        )

        typer.secho(
            "Impossible de modifier l'utilisateur. "
            "Consultez les logs pour plus de détails.",
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    finally:
        session.close()


@user_cli.command(
    "enable",
    help="Activer un utilisateur.",
)
def enable_user(
    username: str,
) -> None:
    session = SessionLocal()

    try:
        service = AuthService(session)

        service.enable_user(
            username,
        )

        typer.secho(
            f"Utilisateur activé : {username}",
            fg=typer.colors.GREEN,
        )

    except UserNotFoundError as exc:
        typer.secho(
            str(exc),
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    except Exception:
        session.rollback()

        logger.exception(
            "Failed to enable user: username=%s",
            username,
        )

        typer.secho(
            "Impossible d'activer l'utilisateur. "
            "Consultez les logs pour plus de détails.",
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    finally:
        session.close()


@user_cli.command(
    "disable",
    help="Désactiver un utilisateur.",
)
def disable_user(
    username: str,
) -> None:
    session = SessionLocal()

    try:
        service = AuthService(session)

        service.disable_user(
            username,
        )

        typer.secho(
            f"Utilisateur désactivé : {username}",
            fg=typer.colors.GREEN,
        )

    except (
        UserNotFoundError,
        LastAdminError,
    ) as exc:
        typer.secho(
            str(exc),
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    except Exception:
        session.rollback()

        logger.exception(
            "Failed to disable user: username=%s",
            username,
        )

        typer.secho(
            "Impossible de désactiver l'utilisateur. "
            "Consultez les logs pour plus de détails.",
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    finally:
        session.close()


@user_cli.command(
    "delete",
    help="Supprimer définitivement un utilisateur.",
)
def delete_user(
    username: str,
    yes: bool = typer.Option(
        False,
        "--yes",
        help="Confirmer la suppression sans demander confirmation.",
    ),
) -> None:
    session = SessionLocal()

    try:
        if not yes:
            confirmed = typer.confirm(
                f"Supprimer définitivement l'utilisateur '{username}' ?",
            )

            if not confirmed:
                typer.echo(
                    "Suppression annulée.",
                )
                return

        service = AuthService(session)

        service.delete_user(
            username,
        )

        typer.secho(
            f"Utilisateur supprimé : {username}",
            fg=typer.colors.GREEN,
        )

    except (
        UserNotFoundError,
        LastAdminError,
    ) as exc:
        typer.secho(
            str(exc),
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    except Exception:
        session.rollback()

        logger.exception(
            "Failed to delete user: username=%s",
            username,
        )

        typer.secho(
            "Impossible de supprimer l'utilisateur. "
            "Consultez les logs pour plus de détails.",
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    finally:
        session.close()
