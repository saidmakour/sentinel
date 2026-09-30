from sentinel.dto.git_credentials import GitCredentials
from sentinel.sources.git.authentication.context import GitAuthContext
from sentinel.sources.git.authentication.none import NoAuthAuthenticator


def test_no_authenticator_can_be_created() -> None:
    authenticator = NoAuthAuthenticator()

    assert authenticator is not None


def test_no_authenticator_returns_auth_context() -> None:
    authenticator = NoAuthAuthenticator()

    context = authenticator.prepare()

    assert isinstance(
        context,
        GitAuthContext,
    )


def test_no_authenticator_returns_empty_context() -> None:
    authenticator = NoAuthAuthenticator()

    context = authenticator.prepare()

    assert context.environment is None


def test_no_authenticator_ignores_credentials() -> None:
    authenticator = NoAuthAuthenticator()

    credentials = GitCredentials(
        username="user",
        password="secret",
    )

    context = authenticator.prepare(
        credentials,
    )

    assert isinstance(
        context,
        GitAuthContext,
    )

    assert context.environment is None
