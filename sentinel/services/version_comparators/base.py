from abc import ABC
from abc import abstractmethod

from sentinel.dto.remediation_info import RemediationInfo
from sentinel.enums.vulnerability_status import VulnerabilityStatus


class BaseVersionComparator(ABC):
    @abstractmethod
    def determine_status(
        self,
        installed_version: str,
        remediation: RemediationInfo,
    ) -> VulnerabilityStatus: ...

    @abstractmethod
    def recommended_version(
        self,
        installed_version: str,
        remediation: RemediationInfo,
    ) -> str | None: ...

    @abstractmethod
    def compare_versions(
        self,
        version_a: str,
        version_b: str,
    ) -> int: ...
