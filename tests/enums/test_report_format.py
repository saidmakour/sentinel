# tests/api/test_report_format.py

from sentinel.enums.report_format import ReportFormat


def test_report_format_values() -> None:
    assert ReportFormat.JSON.value == "json"
    assert ReportFormat.MARKDOWN.value == "markdown"
    assert ReportFormat.CONSOLE.value == "console"
    assert ReportFormat.SARIF.value == "sarif"
