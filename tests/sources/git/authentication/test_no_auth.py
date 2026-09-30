from sentinel.dto.git_credentials import GitCredentials
from sentinel.sources.git.authentication.no_auth import NoAuthAuthenticator


def test_no_auth_authenticator_can_be_created() -> None:
    authenticator = NoAuthAuthenticator()

    assert authenticator is not None


def test_prepare_returns_empty_context() -> None:
    authenticator = NoAuthAuthenticator()

    context = authenticator.prepare()

    assert context.environment is None
    assert context.cleanup is None


def test_prepare_accepts_credentials() -> None:
    authenticator = NoAuthAuthenticator()

    credentials = GitCredentials(
        username="test",
        password="secret",
    )

    context = authenticator.prepare(
        credentials,
    )

    assert context.environment is None
    assert context.cleanup is None
