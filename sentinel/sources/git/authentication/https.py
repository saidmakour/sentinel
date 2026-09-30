from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

from sentinel.dto.git_credentials import GitCredentials
from sentinel.sources.git.authentication.base import GitAuthenticator
from sentinel.sources.git.authentication.context import GitAuthContext


class HttpsAuthenticator(GitAuthenticator):
    def prepare(
        self,
        credentials: GitCredentials | None = None,
    ) -> GitAuthContext:

        if credentials is None:
            return GitAuthContext()

        if not credentials.username and not credentials.password:
            return GitAuthContext()

        username = credentials.username or ""
        password = credentials.password or ""

        fd, script_path = tempfile.mkstemp(
            prefix="sentinel-git-askpass-",
            text=True,
        )

        script = Path(
            script_path,
        )

        try:
            script_content = (
                "#!/bin/sh\n"
                'case "$1" in\n'
                "*Username*)\n"
                f'    printf "%s\\n" "{username}"\n'
                "    ;;\n"
                "*Password*)\n"
                f'    printf "%s\\n" "{password}"\n'
                "    ;;\n"
                "*)\n"
                '    printf "\\n"\n'
                "    ;;\n"
                "esac\n"
            )

            os.write(
                fd,
                script_content.encode(),
            )

        finally:
            os.close(
                fd,
            )

        script.chmod(
            script.stat().st_mode | stat.S_IXUSR,
        )

        def cleanup() -> None:
            script.unlink(
                missing_ok=True,
            )

        return GitAuthContext(
            environment={
                "GIT_ASKPASS": str(script),
                "GIT_TERMINAL_PROMPT": "0",
            },
            cleanup=cleanup,
        )
