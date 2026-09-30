from __future__ import annotations

import typer

from sentinel.config.settings import settings


class Debug:
    @staticmethod
    def enabled() -> bool:
        return settings.debug

    @staticmethod
    def log(message: str) -> None:
        if settings.debug:
            typer.secho(
                f"[DEBUG] {message}",
                fg=typer.colors.BRIGHT_BLACK,
            )

    @staticmethod
    def info(message: str) -> None:
        if settings.debug:
            typer.secho(
                f"[INFO] {message}",
                fg=typer.colors.BRIGHT_BLUE,
            )

    @staticmethod
    def success(message: str) -> None:
        if settings.debug:
            typer.secho(
                f"[ OK ] {message}",
                fg=typer.colors.GREEN,
            )

    @staticmethod
    def warning(message: str) -> None:
        if settings.debug:
            typer.secho(
                f"[WARN] {message}",
                fg=typer.colors.YELLOW,
            )

    @staticmethod
    def error(message: str) -> None:
        if settings.debug:
            typer.secho(
                f"[ERR ] {message}",
                fg=typer.colors.RED,
            )
