import typer

from sentinel.cli.scan_report import ScanReportRenderer
from sentinel.cli.scan_summary import ScanSummaryRenderer
from sentinel.database.session import SessionLocal
from sentinel.log import get_logger
from sentinel.services.report_export_service import ReportExportService
from sentinel.services.report_service import ReportService
from sentinel.services.scan_report_service import ScanReportService

logger = get_logger(__name__)

report_cli = typer.Typer(
    help="Consulter les rapports de scan générés par Sentinel.",
)


@report_cli.command(
    "latest",
    help="Afficher le rapport du dernier scan exécuté.",
)
def latest() -> None:

    session = SessionLocal()

    try:
        report_service = ReportService(
            session,
        )

        report = report_service.get_latest_summary()

        ScanSummaryRenderer.summary(
            report,
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
            "Failed to display latest scan report",
        )

        typer.secho(
            "Unable to display the latest scan report. "
            "Check the logs for more details.",
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    finally:
        session.close()


@report_cli.command(
    "show",
    help="Afficher le rapport d'un scan précis.",
)
def show(
    scan_id: int,
) -> None:

    session = SessionLocal()

    try:
        scan_report_service = ScanReportService(
            session,
        )

        report = scan_report_service.get_report(
            scan_id,
        )

        ScanReportRenderer.summary(
            report,
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
            "Failed to display scan report: scan_id=%s",
            scan_id,
        )

        typer.secho(
            "Unable to display the scan report. "
            "Check the logs for more details.",
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    finally:
        session.close()


@report_cli.command(
    "history",
    help="Afficher l'historique des rapports de scan.",
)
def history() -> None:

    session = SessionLocal()

    try:
        report_service = ReportService(
            session,
        )

        reports = report_service.get_history()

        ScanSummaryRenderer.history(
            reports,
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
            "Failed to display scan history",
        )

        typer.secho(
            "Unable to display scan history. Check the logs for more details.",
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    finally:
        session.close()


@report_cli.command(
    "export",
    help="Exporter le rapport d'un scan.",
)
def export(
    scan_id: int = typer.Option(  # pyright: ignore[reportUnknownMemberType]
        ...,
        "--scan-id",
        help="Identifiant du scan à exporter.",
    ),
    format: str = typer.Option(  # pyright: ignore[reportUnknownMemberType]
        ...,
        "--format",
        help="Format d'export du rapport.",
    ),
) -> None:
    session = SessionLocal()

    try:
        scan_report_service = ScanReportService(
            session,
        )

        export_service = ReportExportService(
            scan_report_service=scan_report_service,
        )

        destination = export_service.export(
            scan_id=scan_id,
            format=format,
        )

        typer.echo(
            f"Rapport exporté : {destination}",
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
            "Failed to export scan report: scan_id=%s format=%s",
            scan_id,
            format,
        )

        typer.secho(
            "Unable to export the scan report. "
            "Check the logs for more details.",
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    finally:
        session.close()
