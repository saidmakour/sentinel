from collections.abc import Callable

from sentinel.exceptions.renderer import RendererNotFoundError
from sentinel.renderers.base import BaseRenderer
from sentinel.renderers.console import ConsoleRenderer
from sentinel.renderers.json import JsonRenderer
from sentinel.renderers.markdown import MarkdownRenderer
from sentinel.renderers.sarif import SarifRenderer

RendererFactory = Callable[[], BaseRenderer]


class RendererRegistry:
    def __init__(self) -> None:
        self._registry: dict[str, RendererFactory] = {
            "console": ConsoleRenderer,
            "json": JsonRenderer,
            "markdown": MarkdownRenderer,
            "sarif": SarifRenderer,
        }

    def create(
        self,
        name: str,
    ) -> BaseRenderer:
        try:
            return self._registry[name.lower()]()
        except KeyError as exc:
            raise RendererNotFoundError(f"Unknown renderer '{name}'.") from exc
