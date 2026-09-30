import pytest

from sentinel.exceptions.renderer import RendererNotFoundError
from sentinel.renderers.console import ConsoleRenderer
from sentinel.renderers.json import JsonRenderer
from sentinel.renderers.markdown import MarkdownRenderer
from sentinel.renderers.registry import RendererRegistry
from sentinel.renderers.sarif import SarifRenderer


def test_registry_can_be_created() -> None:
    registry = RendererRegistry()

    assert registry is not None


def test_create_console_renderer() -> None:
    registry = RendererRegistry()

    renderer = registry.create("console")

    assert isinstance(renderer, ConsoleRenderer)


def test_create_json_renderer() -> None:
    registry = RendererRegistry()

    renderer = registry.create("json")

    assert isinstance(renderer, JsonRenderer)


def test_create_markdown_renderer() -> None:
    registry = RendererRegistry()

    renderer = registry.create("markdown")

    assert isinstance(renderer, MarkdownRenderer)


def test_create_sarif_renderer() -> None:
    registry = RendererRegistry()

    renderer = registry.create("sarif")

    assert isinstance(renderer, SarifRenderer)


def test_create_is_case_insensitive() -> None:
    registry = RendererRegistry()

    renderer = registry.create("JSON")

    assert isinstance(renderer, JsonRenderer)


def test_create_unknown_renderer_raises_value_error() -> None:
    registry = RendererRegistry()

    with pytest.raises(
        RendererNotFoundError,
        match="xml",
    ):
        registry.create("xml")


def test_create_returns_new_instance() -> None:
    registry = RendererRegistry()

    first = registry.create("console")
    second = registry.create("console")

    assert first is not second
