from __future__ import annotations

import os
import shlex
import stat
import tempfile
from pathlib import Path

from sentinel.dto.git_credentials import GitCredentials
from sentinel.sources.git.authentication.base import GitAuthenticator
from sentinel.sources.git.authentication.context import GitAuthContext


class SshAuthenticator(GitAuthenticator):
    def prepare(
        self,
        credentials: GitCredentials | None = None,
    ) -> GitAuthContext:

        if credentials is None:
            return GitAuthContext()

        if not credentials.private_key:
            return GitAuthContext()

        fd, key_path = tempfile.mkstemp(
            prefix="sentinel-git-ssh-",
            text=True,
        )

        private_key = Path(
            key_path,
        )

        try:
            os.write(
                fd,
                credentials.private_key.encode(),
            )

        finally:
            os.close(
                fd,
            )

        private_key.chmod(
            stat.S_IRUSR | stat.S_IWUSR,
        )

        ssh_command = (
            f"ssh -i {shlex.quote(str(private_key))} -o IdentitiesOnly=yes"
        )

        if credentials.passphrase:
            ssh_command += " -o BatchMode=yes"

        def cleanup() -> None:
            private_key.unlink(
                missing_ok=True,
            )

        return GitAuthContext(
            environment={
                "GIT_SSH_COMMAND": ssh_command,
            },
            cleanup=cleanup,
        )
