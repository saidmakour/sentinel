import pytest

from sentinel.dto.git_forge_config import GitForgeConfig
from sentinel.sources.git.forge_registry import GitForgeRegistry


def test_git_forge_config_defaults() -> None:
    config = GitForgeConfig(
        name="github",
        host="github.com",
    )

    assert config.host == "github.com"
    assert config.username is None
    assert config.token is None
    assert config.enabled is True


def test_git_forge_config_accepts_credentials() -> None:
    config = GitForgeConfig(
        name="github",
        host="github.com",
        username="test-user",
        token="test-token",
    )

    assert config.host == "github.com"
    assert config.username == "test-user"
    assert config.token == "test-token"
    assert config.enabled is True


def test_git_forge_config_can_be_disabled() -> None:
    config = GitForgeConfig(
        name="github",
        host="github.com",
        enabled=False,
    )

    assert config.enabled is False


def test_git_forge_config_is_immutable() -> None:
    config = GitForgeConfig(
        name="github",
        host="github.com",
    )

    with pytest.raises(
        AttributeError,
    ):
        config.host = "gitlab.com"


def test_registry_ignores_disabled_forge() -> None:
    forge = GitForgeConfig(
        name="github",
        host="github.com",
        enabled=False,
    )

    registry = GitForgeRegistry(
        forges=[forge],
    )

    result = registry.get_by_host(
        "github.com",
    )

    assert result is None


def test_registry_normalizes_host() -> None:
    forge = GitForgeConfig(
        name="github",
        host="GitHub.COM",
    )

    registry = GitForgeRegistry(
        forges=[forge],
    )

    result = registry.get_by_host(
        " github.com ",
    )

    assert result is forge


def test_registry_returns_matching_forge() -> None:
    github = GitForgeConfig(
        name="github",
        host="github.com",
        token="github-token",
    )

    gitlab = GitForgeConfig(
        name="gitlab",
        host="gitlab.com",
        token="gitlab-token",
    )

    registry = GitForgeRegistry(
        forges=[
            github,
            gitlab,
        ],
    )

    result = registry.get_by_host(
        "gitlab.com",
    )

    assert result is gitlab
    assert result.token == "gitlab-token"


def test_registry_returns_none_when_empty() -> None:
    registry = GitForgeRegistry()

    assert (
        registry.get_by_host(
            "github.com",
        )
        is None
    )
