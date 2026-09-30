import typer
from rich.console import Console
from rich.table import Table

from sentinel.dto.scan_summary import ScanSummary


class ScanSummaryRenderer:
    @staticmethod
    def summary(report: ScanSummary) -> None:
        typer.echo()

        typer.secho(
            "Sentinel Scan Report",
            fg=typer.colors.GREEN,
            bold=True,
        )
        typer.echo()

        typer.secho(
            "Scan completed",
            fg=typer.colors.GREEN,
            bold=True,
        )

        typer.echo(
            f"Scan ID       : {report.scan_id}",
        )

        status = report.status.value.upper()

        color = typer.colors.GREEN if status == "SUCCESS" else typer.colors.RED

        typer.secho(
            f"Scan Status        : {status}",
            fg=color,
        )

        typer.echo(
            f"Dependencies  : {report.dependency_count}",
        )
        typer.echo(
            f"Findings      : {report.finding_count}",
        )

        if report.duration_seconds is not None:
            typer.echo(
                f"Duration      : {report.duration_seconds} s",
            )

        typer.echo()

        typer.secho(
            "Severity",
            fg=typer.colors.BLUE,
            bold=True,
        )

        typer.secho(
            f"  Critical : {report.severity.critical}",
            fg=typer.colors.RED,
        )
        typer.secho(
            f"  High     : {report.severity.high}",
            fg=typer.colors.YELLOW,
        )
        typer.secho(
            f"  Medium   : {report.severity.medium}",
            fg=typer.colors.MAGENTA,
        )
        typer.secho(
            f"  Low      : {report.severity.low}",
            fg=typer.colors.GREEN,
        )

        typer.secho(
            "Status",
            fg=typer.colors.BLUE,
            bold=True,
        )

        for status, count in report.vulnerability_status.items():
            typer.echo(
                f"  {status:<10}: {count}",
            )

        typer.echo()

    @staticmethod
    def history(
        reports: list[ScanSummary],
    ) -> None:
        console = Console()

        if not reports:
            console.print(
                "[yellow]No scan history found.[/yellow]",
            )
            return

        table = Table(
            title="📜 Scan History",
            show_header=True,
            header_style="bold",
        )

        table.add_column(
            "Scan ID",
            justify="right",
        )
        table.add_column("Status")
        table.add_column(
            "Dependencies",
            justify="right",
        )
        table.add_column(
            "Findings",
            justify="right",
        )
        table.add_column(
            "Duration",
            justify="right",
        )
        table.add_column("Source")
        table.add_column("Reference")

        for report in reports:
            status = report.status.value.upper()

            if status == "SUCCESS":
                status_display = f"[green]✓ {status}[/green]"
            elif status == "FAILED":
                status_display = f"[red]✗ {status}[/red]"
            else:
                status_display = f"[yellow]• {status}[/yellow]"

            duration = (
                f"{report.duration_seconds:,} s"
                if report.duration_seconds is not None
                else "-"
            )

            source = report.source_type.value

            reference = (
                report.source_reference if report.source_reference else "-"
            )

            table.add_row(
                str(report.scan_id),
                status_display,
                f"{report.dependency_count:,}",
                f"{report.finding_count:,}",
                duration,
                source,
                reference,
            )

        console.print()
        console.print(table)
