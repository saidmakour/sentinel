import pytest

from sentinel.sources.git.authentication.context import GitAuthContext


def test_git_auth_context_can_be_created() -> None:
    context = GitAuthContext()

    assert context is not None
    assert context.environment is None


def test_git_auth_context_accepts_environment() -> None:
    environment = {
        "GIT_SSH_COMMAND": "ssh -i /tmp/id_rsa",
    }

    context = GitAuthContext(
        environment=environment,
    )

    assert context.environment == environment


def test_git_auth_context_enter_returns_context() -> None:
    context = GitAuthContext(
        environment={
            "GIT_SSH_COMMAND": "ssh",
        },
    )

    with context as entered_context:
        assert entered_context is context
        assert entered_context.environment == {
            "GIT_SSH_COMMAND": "ssh",
        }


def test_git_auth_context_clears_environment_on_exit() -> None:
    context = GitAuthContext(
        environment={
            "GIT_SSH_COMMAND": "ssh",
        },
    )

    with context:
        assert context.environment is not None

    assert context.environment is None


def test_git_auth_context_clears_environment_when_exception_occurs() -> None:
    context = GitAuthContext(
        environment={
            "GIT_SSH_COMMAND": "ssh",
        },
    )

    try:
        with context:
            raise RuntimeError("Git authentication failed")
    except RuntimeError:
        pass

    assert context.environment is None


def test_git_auth_context_exit_accepts_exception_arguments() -> None:
    context = GitAuthContext(
        environment={
            "GIT_SSH_COMMAND": "ssh",
        },
    )

    context.__enter__()

    context.__exit__(
        RuntimeError,
        RuntimeError("test"),
        None,
    )

    assert context.environment is None


def test_git_auth_context_accepts_cleanup() -> None:
    cleaned = False

    def cleanup() -> None:
        nonlocal cleaned
        cleaned = True

    context = GitAuthContext(
        cleanup=cleanup,
    )

    with context:
        assert context.cleanup is cleanup

    assert cleaned is True


def test_git_auth_context_clears_cleanup_on_exit() -> None:
    cleanup_called = False

    def cleanup() -> None:
        nonlocal cleanup_called
        cleanup_called = True

    context = GitAuthContext(
        cleanup=cleanup,
    )

    with context:
        pass

    assert cleanup_called is True
    assert context.cleanup is None


def test_git_auth_context_runs_cleanup_when_exception_occurs() -> None:
    cleanup_called = False

    def cleanup() -> None:
        nonlocal cleanup_called
        cleanup_called = True

    context = GitAuthContext(
        cleanup=cleanup,
    )

    try:
        with context:
            raise RuntimeError(
                "Git authentication failed",
            )
    except RuntimeError:
        pass

    assert cleanup_called is True
    assert context.environment is None
    assert context.cleanup is None


def test_git_auth_context_propagates_cleanup_error() -> None:
    def cleanup() -> None:
        raise RuntimeError(
            "Cleanup failed",
        )

    context = GitAuthContext(
        cleanup=cleanup,
    )

    with pytest.raises(
        RuntimeError,
        match="Cleanup failed",
    ):
        with context:
            pass

    assert context.environment is None
