from sentinel.config.settings import Settings
from sentinel.sources.git.forge_registry_factory import GitForgeRegistryFactory


def test_create_returns_empty_registry_without_gitlab_url() -> None:
    config = Settings(
        gitlab_url="",
        gitlab_token="",
    )

    registry = GitForgeRegistryFactory.create(
        config,
    )

    assert (
        registry.get_by_host(
            "gitlab.com",
        )
        is None
    )


def test_create_registers_gitlab_forge(
    monkeypatch,
) -> None:
    monkeypatch.delenv(
        "GITLAB_URL",
        raising=False,
    )
    monkeypatch.delenv(
        "GITLAB_TOKEN",
        raising=False,
    )

    config = Settings(
        gitlab_url="https://gitlab.example.com",
        gitlab_token="test-token",
    )

    print(
        "CONFIG:",
        config.gitlab_url,
        config.gitlab_token,
    )

    assert config.gitlab_url == "https://gitlab.example.com"
    assert config.gitlab_token == "test-token"

    registry = GitForgeRegistryFactory.create(
        config,
    )

    print(
        "FORGES:",
        registry.forges,
    )

    forge = registry.get_by_host(
        "gitlab.example.com",
    )

    assert forge is not None
    assert forge.host == "gitlab.example.com"
    assert forge.token == "test-token"


def test_create_normalizes_gitlab_host(
    monkeypatch,
) -> None:
    monkeypatch.delenv(
        "GITLAB_URL",
        raising=False,
    )
    monkeypatch.delenv(
        "GITLAB_TOKEN",
        raising=False,
    )

    config = Settings(
        gitlab_url="https://GitLab.Example.COM/",
        gitlab_token="test-token",
    )

    registry = GitForgeRegistryFactory.create(
        config,
    )

    forge = registry.get_by_host(
        "gitlab.example.com",
    )

    assert forge is not None
    assert forge.host == "gitlab.example.com"


def test_create_without_gitlab_token(
    monkeypatch,
) -> None:
    monkeypatch.delenv(
        "GITLAB_URL",
        raising=False,
    )
    monkeypatch.delenv(
        "GITLAB_TOKEN",
        raising=False,
    )

    config = Settings(
        gitlab_url="https://gitlab.example.com",
        gitlab_token="",
    )

    registry = GitForgeRegistryFactory.create(
        config,
    )

    forge = registry.get_by_host(
        "gitlab.example.com",
    )

    assert forge is not None
    assert forge.token is None


def test_extract_host_from_https_url() -> None:
    result = GitForgeRegistryFactory._extract_host(
        "https://gitlab.example.com",
    )

    assert result == "gitlab.example.com"


def test_extract_host_normalizes_host() -> None:
    result = GitForgeRegistryFactory._extract_host(
        "https://GitLab.Example.COM/",
    )

    assert result == "gitlab.example.com"


def test_extract_host_returns_none_for_invalid_url() -> None:
    result = GitForgeRegistryFactory._extract_host(
        "not-a-valid-url",
    )

    assert result is None


def test_factory_debug() -> None:
    config = Settings(
        gitlab_url="https://gitlab.example.com",
        gitlab_token="test-token",
    )

    print("gitlab_url:", repr(config.gitlab_url))
    print("gitlab_token:", repr(config.gitlab_token))

    registry = GitForgeRegistryFactory.create(
        config,
    )

    print("forges:", registry.forges)

    assert config.gitlab_url == "https://gitlab.example.com"
    assert len(registry.forges) == 1
