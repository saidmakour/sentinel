from __future__ import annotations

from sentinel.enums.git_auth_method import GitAuthMethod
from sentinel.sources.git.authentication.base import GitAuthenticator
from sentinel.sources.git.authentication.https import HttpsAuthenticator
from sentinel.sources.git.authentication.no_auth import NoAuthAuthenticator
from sentinel.sources.git.authentication.ssh import SshAuthenticator


class GitAuthenticatorFactory:
    def __init__(
        self,
        no_auth: GitAuthenticator | None = None,
        https: GitAuthenticator | None = None,
        ssh: GitAuthenticator | None = None,
    ) -> None:
        self._authenticators: dict[
            GitAuthMethod,
            GitAuthenticator,
        ] = {
            GitAuthMethod.NONE: no_auth or NoAuthAuthenticator(),
            GitAuthMethod.HTTPS: https or HttpsAuthenticator(),
            GitAuthMethod.SSH: ssh or SshAuthenticator(),
        }

    def create(
        self,
        auth_method: GitAuthMethod,
    ) -> GitAuthenticator:
        return self._authenticators[auth_method]
