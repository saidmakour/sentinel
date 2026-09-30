from enum import StrEnum


class ReportFormat(StrEnum):
    JSON = "json"
    MARKDOWN = "markdown"
    CONSOLE = "console"
    SARIF = "sarif"
