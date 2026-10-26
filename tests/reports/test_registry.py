import pytest

from sentinel.exceptions.renderer import RendererNotFoundError
from sentinel.reports.html import HtmlReportRenderer
from sentinel.reports.json import JsonReportRenderer
from sentinel.reports.markdown import MarkdownReportRenderer
from sentinel.reports.registry import ReportRendererRegistry
from sentinel.reports.sarif import SarifReportRenderer


def test_renderer_registry_can_be_created() -> None:
    registry = ReportRendererRegistry()

    assert registry is not None


@pytest.mark.parametrize(
    ("name", "expected_type"),
    [
        ("markdown", MarkdownReportRenderer),
        ("json", JsonReportRenderer),
        ("sarif", SarifReportRenderer),
        ("html", HtmlReportRenderer),
    ],
)
def test_create_returns_expected_renderer(
    name: str,
    expected_type: type,
) -> None:
    registry = ReportRendererRegistry()

    renderer = registry.create(
        name,
    )

    assert isinstance(
        renderer,
        expected_type,
    )


@pytest.mark.parametrize(
    "name",
    [
        "MARKDOWN",
        "Json",
        "SARIF",
        "Html",
    ],
)
def test_create_is_case_insensitive(
    name: str,
) -> None:
    registry = ReportRendererRegistry()

    renderer = registry.create(
        name,
    )

    assert renderer is not None


def test_create_raises_error_for_unknown_renderer() -> None:
    registry = ReportRendererRegistry()

    with pytest.raises(
        RendererNotFoundError,
        match="Unknown renderer 'xml'.",
    ):
        registry.create(
            "xml",
        )


def test_create_returns_new_renderer_instance_each_time() -> None:
    registry = ReportRendererRegistry()

    first = registry.create(
        "json",
    )

    second = registry.create(
        "json",
    )

    assert first is not second


def test_registry_contains_all_supported_renderers() -> None:
    registry = ReportRendererRegistry()

    supported = {
        "markdown",
        "json",
        "sarif",
        "html",
    }

    assert supported.issubset(
        registry._registry.keys(),
    )
