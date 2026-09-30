from abc import ABC
from abc import abstractmethod

from sentinel.models.repository import Repository
from sentinel.sources.prepared import PreparedSource


class BaseSource(ABC):
    """
    Base class for all source providers.
    """

    @abstractmethod
    def supports(
        self,
        repository: Repository,
    ) -> bool:
        """
        Return True if this provider can prepare the repository.
        """

    @abstractmethod
    def prepare(
        self,
        repository: Repository,
        forge_name: str | None = None,
    ) -> PreparedSource:
        """
        Prepare the repository and return source information.
        """
