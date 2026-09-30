import os
from pathlib import Path

from sentinel.dto.git_credentials import GitCredentials
from sentinel.sources.git.authentication.ssh import SshAuthenticator

PRIVATE_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
test-private-key
-----END OPENSSH PRIVATE KEY-----
"""


def get_private_key_path(
    ssh_command: str,
) -> Path:
    key_argument = (
        ssh_command.split(
            "-i ",
            maxsplit=1,
        )[1]
        .split(
            " -o",
            maxsplit=1,
        )[0]
        .strip()
    )

    return Path(
        key_argument.strip("'\""),
    )


def test_prepare_without_credentials() -> None:
    authenticator = SshAuthenticator()

    context = authenticator.prepare()

    assert context.environment is None


def test_prepare_without_private_key() -> None:
    authenticator = SshAuthenticator()

    credentials = GitCredentials(
        username="git",
    )

    context = authenticator.prepare(
        credentials,
    )

    assert context.environment is None


def test_prepare_creates_ssh_private_key_file() -> None:
    authenticator = SshAuthenticator()

    credentials = GitCredentials(
        private_key=PRIVATE_KEY,
    )

    context = authenticator.prepare(
        credentials,
    )

    assert context.environment is not None
    assert "GIT_SSH_COMMAND" in context.environment

    ssh_command = context.environment["GIT_SSH_COMMAND"]

    assert "-i" in ssh_command
    assert "-o IdentitiesOnly=yes" in ssh_command

    key_path = get_private_key_path(
        ssh_command,
    )

    assert key_path.exists()
    assert key_path.is_file()

    context.cleanup()

    assert not key_path.exists()


def test_prepare_writes_private_key_content() -> None:
    authenticator = SshAuthenticator()

    credentials = GitCredentials(
        private_key=PRIVATE_KEY,
    )

    context = authenticator.prepare(
        credentials,
    )

    assert context.environment is not None

    ssh_command = context.environment["GIT_SSH_COMMAND"]

    key_path = get_private_key_path(
        ssh_command,
    )

    assert (
        key_path.read_text(
            encoding="utf-8",
        )
        == PRIVATE_KEY
    )

    context.cleanup()


def test_prepare_cleanup_removes_private_key() -> None:
    authenticator = SshAuthenticator()

    credentials = GitCredentials(
        private_key=PRIVATE_KEY,
    )

    context = authenticator.prepare(
        credentials,
    )

    assert context.environment is not None

    ssh_command = context.environment["GIT_SSH_COMMAND"]

    key_path = get_private_key_path(
        ssh_command,
    )

    assert key_path.exists()

    context.cleanup()

    assert not key_path.exists()


def test_prepare_cleanup_is_idempotent() -> None:
    authenticator = SshAuthenticator()

    credentials = GitCredentials(
        private_key=PRIVATE_KEY,
    )

    context = authenticator.prepare(
        credentials,
    )

    context.cleanup()


def test_prepare_with_passphrase_enables_batch_mode() -> None:
    authenticator = SshAuthenticator()

    credentials = GitCredentials(
        private_key=PRIVATE_KEY,
        passphrase="secret",
    )

    context = authenticator.prepare(
        credentials,
    )

    assert context.environment is not None

    ssh_command = context.environment["GIT_SSH_COMMAND"]

    assert "-o BatchMode=yes" in ssh_command

    context.cleanup()


def test_prepare_private_key_file_has_restricted_permissions_on_unix() -> None:

    if os.name == "nt":
        return

    authenticator = SshAuthenticator()

    credentials = GitCredentials(
        private_key=PRIVATE_KEY,
    )

    context = authenticator.prepare(
        credentials,
    )

    assert context.environment is not None

    ssh_command = context.environment["GIT_SSH_COMMAND"]

    key_path = get_private_key_path(
        ssh_command,
    )

    mode = key_path.stat().st_mode

    assert mode & 0o077 == 0

    context.cleanup()
