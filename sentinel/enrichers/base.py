from abc import ABC
from abc import abstractmethod

from sentinel.dto.vulnerability_info import VulnerabilityInfo


class BaseEnricher(ABC):
    @abstractmethod
    def enrich(
        self,
        findings: list[VulnerabilityInfo],
    ) -> None:
        """
        Enrich vulnerabilities in place.
        """
