from sentinel.dto.git_credentials import GitCredentials
from sentinel.sources.git.authentication.base import GitAuthenticator
from sentinel.sources.git.authentication.context import GitAuthContext


class NoAuthAuthenticator(GitAuthenticator):
    def prepare(
        self,
        credentials: GitCredentials | None = None,
    ) -> GitAuthContext:
        return GitAuthContext()
