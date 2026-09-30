from abc import ABC
from abc import abstractmethod

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.provider import Provider


class BaseProvider(ABC):
    """
    Base class for vulnerability providers.
    """

    name: Provider

    @abstractmethod
    def scan(
        self,
        dependency: ScannedDependency,
    ) -> list[VulnerabilityInfo]:
        """
        Search vulnerabilities for a dependency.
        """
