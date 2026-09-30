from pathlib import Path

from sentinel.dto.git_credentials import GitCredentials
from sentinel.sources.git.authentication.context import GitAuthContext
from sentinel.sources.git.authentication.https import HttpsAuthenticator


def test_https_authenticator_can_be_created() -> None:
    authenticator = HttpsAuthenticator()

    assert authenticator is not None


def test_prepare_without_credentials_returns_empty_context() -> None:
    authenticator = HttpsAuthenticator()

    context = authenticator.prepare()

    assert isinstance(
        context,
        GitAuthContext,
    )

    assert context.environment is None
    assert context.cleanup is None


def test_prepare_with_empty_credentials_returns_empty_context() -> None:
    authenticator = HttpsAuthenticator()

    credentials = GitCredentials()

    context = authenticator.prepare(
        credentials,
    )

    assert context.environment is None
    assert context.cleanup is None


def test_prepare_creates_askpass_environment() -> None:
    authenticator = HttpsAuthenticator()

    credentials = GitCredentials(
        username="test-user",
        password="test-password",
    )

    context = authenticator.prepare(
        credentials,
    )

    assert context.environment is not None

    assert context.environment["GIT_TERMINAL_PROMPT"] == "0"

    askpass = context.environment["GIT_ASKPASS"]

    assert Path(
        askpass,
    ).exists()


def test_prepare_creates_askpass_script() -> None:
    authenticator = HttpsAuthenticator()

    credentials = GitCredentials(
        username="test-user",
        password="test-password",
    )

    context = authenticator.prepare(
        credentials,
    )

    assert context.environment is not None

    script = Path(
        context.environment["GIT_ASKPASS"],
    )

    assert script.exists()
    assert script.is_file()


def test_askpass_script_contains_credentials() -> None:
    authenticator = HttpsAuthenticator()

    credentials = GitCredentials(
        username="test-user",
        password="test-password",
    )

    context = authenticator.prepare(
        credentials,
    )

    assert context.environment is not None

    script = Path(
        context.environment["GIT_ASKPASS"],
    )

    content = script.read_text(
        encoding="utf-8",
    )

    assert "test-user" in content
    assert "test-password" in content


def test_cleanup_removes_askpass_script() -> None:
    authenticator = HttpsAuthenticator()

    credentials = GitCredentials(
        username="test-user",
        password="test-password",
    )

    context = authenticator.prepare(
        credentials,
    )

    assert context.environment is not None

    script = Path(
        context.environment["GIT_ASKPASS"],
    )

    assert script.exists()

    with context:
        assert script.exists()

    assert not script.exists()


def test_cleanup_removes_askpass_script_when_git_operation_fails() -> None:
    authenticator = HttpsAuthenticator()

    credentials = GitCredentials(
        username="test-user",
        password="test-password",
    )

    context = authenticator.prepare(
        credentials,
    )

    assert context.environment is not None

    script = Path(
        context.environment["GIT_ASKPASS"],
    )

    try:
        with context:
            assert script.exists()

            raise RuntimeError(
                "Git clone failed",
            )

    except RuntimeError:
        pass

    assert not script.exists()
