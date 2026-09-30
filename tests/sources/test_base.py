import pytest

from sentinel.sources.base import BaseSource


def test_base_source_cannot_be_instantiated() -> None:
    with pytest.raises(TypeError):
        BaseSource()
