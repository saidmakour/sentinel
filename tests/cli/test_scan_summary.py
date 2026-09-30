from types import SimpleNamespace
from unittest.mock import patch

import typer

from sentinel.cli.scan_summary import ScanSummaryRenderer
from sentinel.enums.scan_status import ScanStatus


def make_report(
    *,
    scan_id=42,
    status=ScanStatus.SUCCESS,
    dependency_count=10,
    finding_count=3,
    duration_seconds=17,
    critical=1,
    high=1,
    medium=1,
    low=0,
):
    severity = SimpleNamespace(
        critical=critical,
        high=high,
        medium=medium,
        low=low,
    )
    return SimpleNamespace(
        scan_id=scan_id,
        status=status,
        dependency_count=dependency_count,
        finding_count=finding_count,
        duration_seconds=duration_seconds,
        severity=severity,
        vulnerability_status={},
    )


def _echo_messages(mock_echo):
    return [args[0] for args, _ in mock_echo.call_args_list if args]


def _secho_calls(mock_secho):
    return [(args, kwargs) for args, kwargs in mock_secho.call_args_list]


def test_summary_renders_success_report():
    report = make_report()

    with (
        patch("sentinel.cli.scan_summary.typer.echo") as mock_echo,
        patch("sentinel.cli.scan_summary.typer.secho") as mock_secho,
    ):
        ScanSummaryRenderer.summary(report)

        echo_messages = _echo_messages(mock_echo)
        secho_calls = _secho_calls(mock_secho)

        assert "Scan ID       : 42" in echo_messages
        assert "Dependencies  : 10" in echo_messages
        assert "Findings      : 3" in echo_messages
        assert "Duration      : 17 s" in echo_messages

        assert (
            ("Sentinel Scan Report",),
            {"fg": typer.colors.GREEN, "bold": True},
        ) in secho_calls

        assert (
            ("Scan completed",),
            {"fg": typer.colors.GREEN, "bold": True},
        ) in secho_calls

        assert (
            ("Scan Status        : SUCCESS",),
            {"fg": typer.colors.GREEN},
        ) in secho_calls
        assert (
            ("Severity",),
            {"fg": typer.colors.BLUE, "bold": True},
        ) in secho_calls
        assert (("  Critical : 1",), {"fg": typer.colors.RED}) in secho_calls
        assert (
            ("  High     : 1",),
            {"fg": typer.colors.YELLOW},
        ) in secho_calls
        assert (
            ("  Medium   : 1",),
            {"fg": typer.colors.MAGENTA},
        ) in secho_calls
        assert (("  Low      : 0",), {"fg": typer.colors.GREEN}) in secho_calls


def test_summary_renders_failed_status_in_red():
    report = make_report(status=ScanStatus.FAILED)

    with (
        patch("sentinel.cli.scan_summary.typer.echo"),
        patch("sentinel.cli.scan_summary.typer.secho") as mock_secho,
    ):
        ScanSummaryRenderer.summary(report)

        secho_calls = _secho_calls(mock_secho)

        assert (
            ("Scan Status        : FAILED",),
            {"fg": typer.colors.RED},
        ) in secho_calls


def test_summary_does_not_render_duration_when_none():
    report = make_report(duration_seconds=None)

    with (
        patch("sentinel.cli.scan_summary.typer.echo") as mock_echo,
        patch("sentinel.cli.scan_summary.typer.secho"),
    ):
        ScanSummaryRenderer.summary(report)

        echo_messages = _echo_messages(mock_echo)

        assert not any(
            message.startswith("Duration") for message in echo_messages
        )
