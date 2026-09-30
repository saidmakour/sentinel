from collections import Counter

import typer
from rich.console import Console

from sentinel.cli.scan_summary import ScanSummaryRenderer
from sentinel.database.session import SessionLocal
from sentinel.log import get_logger
from sentinel.services.findings_service import FindingService
from sentinel.services.report_service import ReportService
from sentinel.services.scan_service import ScanService

logger = get_logger(__name__)

scan_cli = typer.Typer(
    help="Lancer des scans sur les dépôts enregistrés.",
)

console = Console()


@scan_cli.command(
    "run",
    help="Lancer un scan sur un dépôt d'application.",
)
def run(
    application_id: int,
    repository_name: str,
    profile_name: str = "default",
    forge_name: str | None = typer.Option(  # pyright: ignore[reportUnknownMemberType]
        None,
        "--forge",
        help="Nom de la forge Git à utiliser.",
    ),
) -> None:

    session = SessionLocal()

    try:
        service = ScanService(
            session,
        )

        report_service = ReportService(
            session,
        )

        with console.status(
            f"[bold green]Scanning repository : {repository_name} ...",
            spinner="dots",
        ):
            scan = service.run(
                application_id,
                repository_name,
                profile_name,
                forge_name=forge_name,
            )

        report = report_service.get_scan_summary(
            scan.id,
        )
        finding_service = FindingService(session)

        findings = finding_service.list_by_scan(scan.id)

        counter = Counter(
            (
                finding.identifier,
                finding.dependency_name,
                finding.dependency_version,
            )
            for finding in findings
        )

        unique_cves = len({finding.identifier for finding in findings})

        print()
        print("===== AUDIT =====")
        print(f"Occurrences              : {len(findings)}")
        print(f"Unique findings          : {len(counter)}")
        print(f"Unique vulnerabilities   : {unique_cves}")
        print(
            f"Duplicates               : {sum(v > 1 for v in counter.values())}"
        )

        duplicates = [
            (identifier, count)
            for identifier, count in counter.most_common(20)
            if count > 1
        ]

        print()

        if duplicates:
            print("Top repeated findings")

            for identifier, count in duplicates:
                print(identifier, count)
        else:
            print("No duplicate findings detected")

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
            "Scan command failed: application_id=%s repository=%s "
            "profile=%s forge=%s",
            application_id,
            repository_name,
            profile_name,
            forge_name,
        )

        typer.secho(
            "Scan failed. Check the logs for more details.",
            fg=typer.colors.RED,
        )

        raise typer.Exit(
            code=1,
        ) from None

    finally:
        session.close()
