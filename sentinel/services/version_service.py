from sentinel.dto.remediation_info import RemediationInfo
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.vulnerability_status import VulnerabilityStatus
from sentinel.plugins.defaults import create_plugin_registry
from sentinel.services.version_comparators.base import BaseVersionComparator
from sentinel.services.version_comparators.registry import (
    VersionComparatorRegistry,
)


class VersionService:
    def __init__(
        self,
        comparators: dict[
            Ecosystem,
            BaseVersionComparator,
        ]
        | None = None,
        registry: VersionComparatorRegistry | None = None,
    ) -> None:
        if registry is not None:
            self.registry = registry
        elif comparators is not None:
            self.registry = VersionComparatorRegistry(
                comparators,
            )
        else:
            self.registry = VersionComparatorRegistry(
                create_plugin_registry().comparators,
            )

    @property
    def comparators(
        self,
    ) -> dict[Ecosystem, BaseVersionComparator]:
        return self.registry.comparators

    def determine_status(
        self,
        ecosystem: Ecosystem,
        installed_version: str,
        remediation: RemediationInfo | None,
    ) -> VulnerabilityStatus:
        if remediation is None:
            return VulnerabilityStatus.UNKNOWN

        comparator = self.registry.get(ecosystem)

        if comparator is None:
            return VulnerabilityStatus.UNKNOWN

        return comparator.determine_status(
            installed_version=installed_version,
            remediation=remediation,
        )

    def recommended_version(
        self,
        ecosystem: Ecosystem,
        installed_version: str,
        remediation: RemediationInfo | None,
    ) -> str | None:
        if remediation is None:
            return None

        comparator = self.registry.get(ecosystem)

        if comparator is None:
            return None

        return comparator.recommended_version(
            installed_version=installed_version,
            remediation=remediation,
        )

    def compare_versions(
        self,
        ecosystem: Ecosystem,
        version_a: str,
        version_b: str,
    ) -> int:
        comparator = self.registry.get(ecosystem)

        if comparator is None:
            return 0

        return comparator.compare_versions(
            version_a=version_a,
            version_b=version_b,
        )
