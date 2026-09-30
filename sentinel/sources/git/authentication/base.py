from abc import ABC
from abc import abstractmethod

from sentinel.dto.git_credentials import GitCredentials
from sentinel.sources.git.authentication.context import GitAuthContext


class GitAuthenticator(ABC):
    @abstractmethod
    def prepare(
        self,
        credentials: GitCredentials | None = None,
    ) -> GitAuthContext:
        """
        Prepare the authentication context for Git operations.
        """
        ...
