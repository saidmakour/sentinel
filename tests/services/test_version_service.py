from unittest.mock import MagicMock
from unittest.mock import Mock

from sentinel.dto.remediation_info import RemediationInfo
from sentinel.dto.remediation_info import RemediationRule
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.vulnerability_status import VulnerabilityStatus
from sentinel.plugins.python.version_comparator import PyPIVersionComparator
from sentinel.services.version_comparators.base import BaseVersionComparator
from sentinel.services.version_comparators.registry import (
    VersionComparatorRegistry,
)
from sentinel.services.version_service import VersionService


def test_version_service_can_be_created_1() -> None:
    service = VersionService()

    assert service is not None


def test_version_service_uses_ecosystem_comparator() -> None:
    comparator = Mock(
        spec=BaseVersionComparator,
    )

    comparator.determine_status.return_value = VulnerabilityStatus.OPEN

    service = VersionService(
        comparators={
            Ecosystem.PYPI: comparator,
        },
    )

    remediation = RemediationInfo()

    result = service.determine_status(
        ecosystem=Ecosystem.PYPI,
        installed_version="1.0.0",
        remediation=remediation,
    )

    assert result == VulnerabilityStatus.OPEN

    comparator.determine_status.assert_called_once_with(
        installed_version="1.0.0",
        remediation=remediation,
    )


def test_unknown_when_remediation_is_none() -> None:
    service = VersionService()

    result = service.determine_status(
        ecosystem=Ecosystem.PYPI,
        installed_version="1.0.0",
        remediation=None,
    )

    assert result == VulnerabilityStatus.UNKNOWN


def test_unknown_when_ecosystem_has_no_comparator() -> None:
    service = VersionService(
        comparators={},
    )

    result = service.determine_status(
        ecosystem=Ecosystem.NPM,
        installed_version="1.0.0",
        remediation=RemediationInfo(),
    )

    assert result == VulnerabilityStatus.UNKNOWN


def test_version_service_can_be_created() -> None:
    service = VersionService()

    assert service is not None
    assert service.registry.supports(Ecosystem.PYPI)


def test_determine_status_returns_unknown_without_remediation() -> None:
    comparator = MagicMock()

    service = VersionService(
        comparators={
            Ecosystem.PYPI: comparator,
        },
    )

    result = service.determine_status(
        ecosystem=Ecosystem.PYPI,
        installed_version="2.32.3",
        remediation=None,
    )

    assert result == VulnerabilityStatus.UNKNOWN

    comparator.determine_status.assert_not_called()


def test_determine_status_returns_unknown_for_unsupported_ecosystem() -> None:
    pypi_comparator = MagicMock()

    service = VersionService(
        comparators={
            Ecosystem.PYPI: pypi_comparator,
        },
    )

    result = service.determine_status(
        ecosystem=Ecosystem.NPM,
        installed_version="1.0.0",
        remediation=RemediationInfo(),
    )

    assert result == VulnerabilityStatus.UNKNOWN

    pypi_comparator.determine_status.assert_not_called()


def test_determine_status_delegates_to_comparator() -> None:
    comparator = MagicMock()

    comparator.determine_status.return_value = VulnerabilityStatus.OPEN

    service = VersionService(
        comparators={
            Ecosystem.PYPI: comparator,
        },
    )

    remediation = RemediationInfo()

    result = service.determine_status(
        ecosystem=Ecosystem.PYPI,
        installed_version="2.32.3",
        remediation=remediation,
    )

    assert result == VulnerabilityStatus.OPEN

    comparator.determine_status.assert_called_once_with(
        installed_version="2.32.3",
        remediation=remediation,
    )


def test_determine_status_returns_resolved_status() -> None:
    comparator = MagicMock()

    comparator.determine_status.return_value = VulnerabilityStatus.RESOLVED

    service = VersionService(
        comparators={
            Ecosystem.PYPI: comparator,
        },
    )

    remediation = RemediationInfo()

    result = service.determine_status(
        ecosystem=Ecosystem.PYPI,
        installed_version="2.32.4",
        remediation=remediation,
    )

    assert result == VulnerabilityStatus.RESOLVED

    comparator.determine_status.assert_called_once_with(
        installed_version="2.32.4",
        remediation=remediation,
    )


def test_version_service_accepts_custom_comparators() -> None:
    comparator = MagicMock()

    service = VersionService(
        comparators={
            Ecosystem.PYPI: comparator,
        },
    )

    assert service.registry.get(Ecosystem.PYPI) is comparator


def test_npm_uses_npm_comparator() -> None:
    service = VersionService()

    status = service.determine_status(
        ecosystem=Ecosystem.NPM,
        installed_version="1.5.0",
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    fixed="2.0.0",
                ),
            ],
        ),
    )

    assert status == VulnerabilityStatus.OPEN


def test_version_service_registers_php_comparator() -> None:
    service = VersionService()

    assert service.registry.supports(Ecosystem.COMPOSER)


def test_version_service_registers_java_comparator() -> None:
    service = VersionService()

    assert service.registry.supports(Ecosystem.MAVEN)


def test_version_service_uses_php_comparator() -> None:
    service = VersionService()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                fixed="8.3.10",
            ),
        ],
    )

    result = service.determine_status(
        ecosystem=Ecosystem.COMPOSER,
        installed_version="8.3.5",
        remediation=remediation,
    )

    assert result == VulnerabilityStatus.OPEN


def test_version_service_uses_java_comparator() -> None:
    service = VersionService()

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                fixed="21.0.5",
            ),
        ],
    )

    result = service.determine_status(
        ecosystem=Ecosystem.MAVEN,
        installed_version="21.0.4",
        remediation=remediation,
    )

    assert result == VulnerabilityStatus.OPEN


def test_recommended_version_returns_none_without_remediation() -> None:
    service = VersionService()

    result = service.recommended_version(
        ecosystem=Ecosystem.PYPI,
        installed_version="2.31.0",
        remediation=None,
    )

    assert result is None


def test_recommended_version_returns_none_for_unsupported_ecosystem() -> None:
    service = VersionService(
        comparators={
            Ecosystem.PYPI: PyPIVersionComparator(),
        },
    )

    remediation = RemediationInfo(
        rules=[
            RemediationRule(
                introduced="2.0.0",
                fixed="2.32.0",
                affected_range="<2.32.0",
            ),
        ],
    )

    result = service.recommended_version(
        ecosystem=Ecosystem.GOLANG,
        installed_version="2.31.0",
        remediation=remediation,
    )

    assert result is None


def test_compare_versions_delegates_to_comparator() -> None:
    service = VersionService()

    result = service.compare_versions(
        ecosystem=Ecosystem.PYPI,
        version_a="2.31.0",
        version_b="2.32.0",
    )

    assert result < 0


def test_compare_versions_returns_zero_for_equal_versions() -> None:
    service = VersionService()

    result = service.compare_versions(
        ecosystem=Ecosystem.PYPI,
        version_a="2.32.0",
        version_b="2.32.0",
    )

    assert result == 0


def test_compare_versions_returns_zero_for_unsupported_ecosystem() -> None:
    service = VersionService(
        comparators={},
    )

    result = service.compare_versions(
        ecosystem=Ecosystem.PYPI,
        version_a="2.31.0",
        version_b="2.32.0",
    )

    assert result == 0


def test_version_service_uses_plugin_registry() -> None:
    service = VersionService()

    assert service.registry.get(Ecosystem.PYPI) is not None
    assert service.registry.get(Ecosystem.NPM) is not None
    assert service.registry.get(Ecosystem.COMPOSER) is not None
    assert service.registry.get(Ecosystem.MAVEN) is not None


def test_version_service_accepts_registry() -> None:
    comparator = MagicMock()

    registry = VersionComparatorRegistry(
        {
            Ecosystem.PYPI: comparator,
        },
    )

    service = VersionService(
        registry=registry,
    )

    assert service.registry is registry
    assert service.comparators[Ecosystem.PYPI] is comparator
