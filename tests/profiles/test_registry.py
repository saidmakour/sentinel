import pytest

from sentinel.profiles.default import DefaultProfile
from sentinel.profiles.registry import ProfileRegistry


def test_registry_can_create_default_profile() -> None:
    registry = ProfileRegistry()

    profile = registry.create(
        "default",
    )

    assert isinstance(
        profile,
        DefaultProfile,
    )


def test_registry_unknown_profile() -> None:
    registry = ProfileRegistry()

    with pytest.raises(ValueError):
        registry.create(
            "unknown",
        )
