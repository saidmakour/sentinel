from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from sentinel.dto.scan_report import ScanReport


class ScanReportRenderer:
    def __init__(
        self,
        console: Console | None = None,
    ) -> None:
        self.console = console or Console()

    def render(
        self,
        report: ScanReport,
    ) -> None:
        self._render_header()
        self._render_scan_information(report)
        self._render_risk(report)
        self._render_dependency_security(report)
        self._render_recommendations(report)

    @staticmethod
    def summary(
        report: ScanReport,
    ) -> None:
        renderer = ScanReportRenderer()
        renderer.render(report)

    def _render_header(self) -> None:
        self.console.print(
            Panel(
                "[bold cyan]🔐 Sentinel Scan Report[/bold cyan]",
                expand=False,
                border_style="cyan",
            )
        )

    def _render_scan_information(
        self,
        report: ScanReport,
    ) -> None:
        scan_status = self._scan_status(
            report.status.value,
        )

        security_status = self._security_status(
            report.security_status.value,
        )

        table = Table(
            show_header=False,
            box=None,
            padding=(0, 1),
        )

        table.add_column(
            "Label",
            style="bold",
        )
        table.add_column("Value")

        table.add_row(
            "Scan ID",
            str(report.scan_id),
        )
        table.add_row(
            "Repository ID",
            str(report.repository_id),
        )
        table.add_row(
            "Profile",
            report.profile_name,
        )
        table.add_row(
            "Engine Version",
            report.engine_version,
        )
        table.add_row(
            "Scan Status",
            scan_status,
        )
        table.add_row(
            "Security Status",
            security_status,
        )
        table.add_row(
            "Duration",
            self._format_duration(
                report.duration_seconds,
            ),
        )

        self.console.print()
        self.console.print(
            Panel(
                table,
                title="📋 Scan",
                border_style="blue",
            )
        )

        if report.error_message:
            self.console.print(
                Panel(
                    f"[red]{report.error_message}[/red]",
                    title="❌ Scan Error",
                    border_style="red",
                )
            )

    def _render_risk(
        self,
        report: ScanReport,
    ) -> None:
        table = Table(
            show_header=False,
            box=None,
            padding=(0, 1),
        )

        table.add_column(
            "Severity",
            style="bold",
        )
        table.add_column(
            "Count",
            justify="right",
        )

        table.add_row(
            "🔴 Critical",
            self._format_number(
                report.critical_count,
            ),
        )
        table.add_row(
            "🟠 High",
            self._format_number(
                report.high_count,
            ),
        )
        table.add_row(
            "🟡 Medium",
            self._format_number(
                report.medium_count,
            ),
        )
        table.add_row(
            "🔵 Low",
            self._format_number(
                report.low_count,
            ),
        )

        self.console.print()
        self.console.print(
            Panel(
                table,
                title=(
                    f"📊 Risk  "
                    f"[bold]Score: "
                    f"{self._format_number(report.risk_score)}[/bold]"
                ),
                border_style="yellow",
            )
        )

    def _render_dependency_security(
        self,
        report: ScanReport,
    ) -> None:
        self.console.print()

        if not report.dependency_summaries:
            self.console.print(
                Panel(
                    "[green]✓ No dependency security issues found.[/green]",
                    title="📦 Dependency Security",
                    border_style="green",
                )
            )
            return

        table = Table(
            title="📦 Dependency Security",
            show_lines=True,
            header_style="bold cyan",
        )

        table.add_column(
            "Status",
            justify="center",
            no_wrap=True,
        )
        table.add_column(
            "Dependency",
            style="bold",
        )
        table.add_column(
            "Version",
        )
        table.add_column(
            "Ecosystem",
        )
        table.add_column(
            "Findings",
            justify="right",
        )
        table.add_column(
            "Open",
            justify="right",
        )
        table.add_column(
            "Recommended",
        )

        for summary in report.dependency_summaries:
            status = self._dependency_status(
                summary.security_status.value,
            )

            recommended = (
                summary.recommended_version
                if summary.recommended_version is not None
                else "-"
            )

            table.add_row(
                status,
                summary.dependency_name,
                summary.installed_version,
                summary.ecosystem.value,
                self._format_number(
                    summary.finding_count,
                ),
                self._format_number(
                    summary.open_finding_count,
                ),
                recommended,
            )

        self.console.print(table)

    def _render_recommendations(
        self,
        report: ScanReport,
    ) -> None:
        recommendations: list[str] = []

        for summary in report.dependency_summaries:
            if summary.recommended_version is None:
                continue

            if summary.security_status.value != "at_risk":
                continue

            recommendations.append(
                "Upgrade "
                f"[bold]{summary.dependency_name}[/bold] "
                f"from [yellow]{summary.installed_version}[/yellow] "
                f"to [green]{summary.recommended_version}[/green]."
            )

        self.console.print()

        if not recommendations:
            self.console.print(
                Panel(
                    "[green]✓ No immediate remediation actions required.[/green]",
                    title="💡 Recommended Actions",
                    border_style="green",
                )
            )
            return

        lines = [f"→ {recommendation}" for recommendation in recommendations]

        self.console.print(
            Panel(
                "\n".join(lines),
                title="💡 Recommended Actions",
                border_style="green",
            )
        )

    @staticmethod
    def _scan_status(
        status: str,
    ) -> Text:
        normalized = status.lower()

        match normalized:
            case "success":
                return Text(
                    "✓ SUCCESS",
                    style="bold green",
                )

            case "failed" | "failure":
                return Text(
                    "✗ FAILED",
                    style="bold red",
                )

            case "running":
                return Text(
                    "● RUNNING",
                    style="bold yellow",
                )

            case "pending":
                return Text(
                    "○ PENDING",
                    style="bold yellow",
                )

            case _:
                return Text(
                    status.upper(),
                    style="bold white",
                )

    @staticmethod
    def _security_status(
        status: str,
    ) -> Text:
        normalized = status.lower()

        match normalized:
            case "secure":
                return Text(
                    "✓ SECURE",
                    style="bold green",
                )

            case "at_risk":
                return Text(
                    "⚠ AT RISK",
                    style="bold yellow",
                )

            case "critical":
                return Text(
                    "✗ CRITICAL",
                    style="bold red",
                )

            case _:
                return Text(
                    status.upper(),
                    style="bold white",
                )

    @staticmethod
    def _dependency_status(
        status: str,
    ) -> Text:
        normalized = status.lower()

        match normalized:
            case "secure":
                return Text(
                    "✓ SECURE",
                    style="bold green",
                )

            case "at_risk":
                return Text(
                    "⚠ AT RISK",
                    style="bold yellow",
                )

            case "critical":
                return Text(
                    "✗ CRITICAL",
                    style="bold red",
                )

            case _:
                return Text(
                    status.upper(),
                    style="bold white",
                )

    @staticmethod
    def _format_number(
        value: int,
    ) -> str:
        return f"{value:,}"

    @staticmethod
    def _format_duration(
        duration_seconds: int | float | None,
    ) -> str:
        if duration_seconds is None:
            return "N/A"

        if duration_seconds < 60:
            return f"{duration_seconds:.0f} s"

        minutes = int(duration_seconds // 60)
        seconds = int(duration_seconds % 60)

        return f"{minutes} min {seconds} s"
