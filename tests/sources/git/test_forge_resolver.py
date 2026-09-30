from sentinel.config.settings import Settings
from sentinel.dto.git_forge_config import GitForgeConfig
from sentinel.sources.git.forge_registry import GitForgeRegistry
from sentinel.sources.git.forge_resolver import GitForgeResolver


def test_resolve_by_remote_host() -> None:
    forge = GitForgeConfig(
        name="github",
        host="github.com",
        token="github-token",
    )

    registry = GitForgeRegistry(
        forges=[forge],
    )

    settings = Settings(
        GIT_FORGE=None,
    )

    resolver = GitForgeResolver(
        registry=registry,
        settings=settings,
    )

    result = resolver.resolve(
        "https://github.com/example/backend.git",
    )

    assert result is forge


def test_resolve_by_explicit_forge_name() -> None:
    forge = GitForgeConfig(
        name="github",
        host="github.com",
        token="github-token",
    )

    registry = GitForgeRegistry(
        forges=[forge],
    )

    resolver = GitForgeResolver(
        registry,
    )

    result = resolver.resolve(
        "https://gitlab.com/example/backend.git",
        forge_name="github",
    )

    assert result is forge


def test_explicit_forge_has_priority_over_remote_host() -> None:
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

    resolver = GitForgeResolver(
        registry,
    )

    result = resolver.resolve(
        "https://gitlab.com/example/backend.git",
        forge_name="github",
    )

    assert result is github


def test_resolve_returns_none_for_unknown_forge() -> None:
    registry = GitForgeRegistry()

    resolver = GitForgeResolver(
        registry,
    )

    result = resolver.resolve(
        "https://github.com/example/backend.git",
        forge_name="github",
    )

    assert result is None


def test_resolve_returns_none_for_unknown_host() -> None:
    registry = GitForgeRegistry()

    resolver = GitForgeResolver(
        registry,
    )

    result = resolver.resolve(
        "https://unknown.example.com/example/backend.git",
    )

    assert result is None


def test_resolve_returns_none_for_invalid_remote_url() -> None:
    registry = GitForgeRegistry()

    resolver = GitForgeResolver(
        registry,
    )

    result = resolver.resolve(
        "not-a-valid-url",
    )

    assert result is None


def test_resolve_uses_settings_forge() -> None:
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

    settings = Settings(
        GIT_FORGE="gitlab",
    )

    resolver = GitForgeResolver(
        registry=registry,
        settings=settings,
    )

    result = resolver.resolve(
        "https://github.com/example/backend.git",
    )

    assert result is gitlab


def test_explicit_forge_has_priority_over_settings() -> None:
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

    settings = Settings(
        GIT_FORGE="gitlab",
    )

    resolver = GitForgeResolver(
        registry=registry,
        settings=settings,
    )

    result = resolver.resolve(
        "https://gitlab.com/example/backend.git",
        forge_name="github",
    )

    assert result is github


def test_resolve_uses_remote_host_when_no_forge_is_configured() -> None:
    github = GitForgeConfig(
        name="github",
        host="github.com",
        token="github-token",
    )

    registry = GitForgeRegistry(
        forges=[github],
    )

    settings = Settings(
        GIT_FORGE=None,
    )

    resolver = GitForgeResolver(
        registry=registry,
        settings=settings,
    )

    result = resolver.resolve(
        "https://github.com/example/backend.git",
    )

    assert result is github
