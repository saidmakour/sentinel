from sentinel.config.settings import Settings
from sentinel.dto.git_credentials import GitCredentials
from sentinel.dto.git_forge_config import GitForgeConfig
from sentinel.sources.git.credentials_provider import GitCredentialsProvider
from sentinel.sources.git.forge_registry import GitForgeRegistry
from sentinel.sources.git.forge_resolver import GitForgeResolver


def create_provider(
    *forges: GitForgeConfig,
) -> GitCredentialsProvider:
    registry = GitForgeRegistry(
        forges=list(forges),
    )

    resolver = GitForgeResolver(
        registry,
        settings=Settings(
            GIT_FORGE=None,
        ),
    )

    return GitCredentialsProvider(
        resolver=resolver,
    )


def test_get_returns_none_for_unknown_forge() -> None:
    provider = create_provider()

    result = provider.get(
        "https://github.com/example/backend.git",
    )

    assert result is None


def test_get_returns_none_for_forge_without_credentials() -> None:
    provider = create_provider(
        GitForgeConfig(
            name="github",
            host="github.com",
        ),
    )

    result = provider.get(
        "https://github.com/example/backend.git",
    )

    assert result is None


def test_get_returns_credentials_for_configured_forge() -> None:

    provider = create_provider(
        GitForgeConfig(
            name="github",
            host="github.com",
            username="test-user",
            token="test-token",
        ),
    )

    result = provider.get(
        "https://github.com/example/backend.git",
    )

    assert result == GitCredentials(
        username="test-user",
        password="test-token",
    )


def test_get_returns_github_credentials() -> None:
    provider = create_provider(
        GitForgeConfig(
            name="github",
            host="github.com",
            username="github-user",
            token="github-token",
        ),
    )

    result = provider.get(
        "https://github.com/example/backend.git",
    )

    assert result is not None
    assert result.username == "github-user"
    assert result.password == "github-token"


def test_get_returns_gitlab_credentials() -> None:
    provider = create_provider(
        GitForgeConfig(
            name="gitlab",
            host="gitlab.com",
            username="gitlab-user",
            token="gitlab-token",
        ),
    )

    result = provider.get(
        "https://gitlab.com/example/backend.git",
    )

    assert result is not None
    assert result.username == "gitlab-user"
    assert result.password == "gitlab-token"


def test_get_returns_none_for_invalid_url() -> None:
    provider = create_provider(
        GitForgeConfig(
            name="github",
            host="github.com",
            username="test-user",
            token="test-token",
        ),
    )

    result = provider.get(
        "not-a-valid-url",
    )

    assert result is None


def test_get_returns_credentials_for_ssh_url() -> None:
    provider = create_provider(
        GitForgeConfig(
            name="github",
            host="github.com",
            username="git",
            token="github-token",
        ),
    )

    result = provider.get(
        "git@github.com:example/backend.git",
    )

    assert result == GitCredentials(
        username="git",
        password="github-token",
    )


def test_get_returns_credentials_for_explicit_forge() -> None:
    github = GitForgeConfig(
        name="github",
        host="github.com",
        username="github-user",
        token="github-token",
    )

    gitlab = GitForgeConfig(
        name="gitlab",
        host="gitlab.com",
        username="gitlab-user",
        token="gitlab-token",
    )

    provider = create_provider(
        github,
        gitlab,
    )

    result = provider.get(
        "https://gitlab.com/example/backend.git",
        forge_name="github",
    )

    assert result == GitCredentials(
        username="github-user",
        password="github-token",
    )
