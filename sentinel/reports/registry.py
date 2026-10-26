from collections.abc import Callable

from sentinel.exceptions.renderer import RendererNotFoundError
from sentinel.reports.base import BaseReportRenderer
from sentinel.reports.html import HtmlReportRenderer
from sentinel.reports.json import JsonReportRenderer
from sentinel.reports.markdown import MarkdownReportRenderer
from sentinel.reports.sarif import SarifReportRenderer

ReportFactory = Callable[[], BaseReportRenderer]


class ReportRendererRegistry:
    def __init__(
        self,
    ) -> None:

        self._registry: dict[str, ReportFactory] = {
            "markdown": MarkdownReportRenderer,
            "json": JsonReportRenderer,
            "sarif": SarifReportRenderer,
            "html": HtmlReportRenderer,
        }

    def create(
        self,
        name: str,
    ) -> BaseReportRenderer:

        try:
            return self._registry[name.lower()]()

        except KeyError as exc:
            raise RendererNotFoundError(f"Unknown renderer '{name}'.") from exc
