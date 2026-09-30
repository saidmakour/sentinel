import pytest

from sentinel.profiles.base import BaseProfile


def test_base_profile_is_abstract() -> None:
    with pytest.raises(TypeError):
        BaseProfile()
