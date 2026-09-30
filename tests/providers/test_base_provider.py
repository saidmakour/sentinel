import pytest

from sentinel.providers.base import BaseProvider


def test_base_provider_is_abstract() -> None:
    with pytest.raises(TypeError):
        BaseProvider()
