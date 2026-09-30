from unittest.mock import Mock

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity
from sentinel.providers.nvd.client import NVDClient
from sentinel.providers.nvd.mapper import NVDMapper
from sentinel.providers.nvd.models import NVDResponse
from sentinel.providers.nvd.provider import NVDProvider


def make_dependency() -> ScannedDependency:
    return ScannedDependency(
        name="django",
        version="5.2.0",
        ecosystem="PyPI",
        source="requirements.txt",
    )


def test_scan_calls_client_and_mapper() -> None:
    dependency = make_dependency()

    client = Mock(
        spec=NVDClient,
    )

    mapper = Mock(
        spec=NVDMapper,
    )

    response = NVDResponse(
        vulnerabilities=[],
    )

    expected = [
        VulnerabilityInfo(
            identifier="CVE-2026-0001",
            aliases=["CVE-2026-0001"],
            dependency_name="requests",
            dependency_version="2.31.0",
            ecosystem=Ecosystem.PYPI,
            summary="Test vulnerability",
            severity=Severity.CRITICAL,
            sources=[Provider.NVD],
            cvss=9.8,
        ),
    ]

    client.query.return_value = response

    mapper.map.return_value = expected

    provider = NVDProvider(
        client=client,
        mapper=mapper,
    )

    result = provider.scan(
        dependency,
    )

    assert result == expected

    client.query.assert_called_once_with(
        package_name="django",
    )

    mapper.map.assert_called_once_with(
        dependency,
        response,
    )


def test_scan_returns_empty_list_when_mapper_returns_empty() -> None:
    dependency = make_dependency()

    client = Mock(
        spec=NVDClient,
    )

    mapper = Mock(
        spec=NVDMapper,
    )

    response = NVDResponse(
        vulnerabilities=[],
    )

    client.query.return_value = response

    mapper.map.return_value = []

    provider = NVDProvider(
        client=client,
        mapper=mapper,
    )

    result = provider.scan(
        dependency,
    )

    assert result == []

    client.query.assert_called_once_with(
        package_name="django",
    )

    mapper.map.assert_called_once_with(
        dependency,
        response,
    )


def test_scan_propagates_client_error() -> None:
    dependency = make_dependency()

    client = Mock(
        spec=NVDClient,
    )

    mapper = Mock(
        spec=NVDMapper,
    )

    client.query.side_effect = RuntimeError(
        "NVD unavailable",
    )

    provider = NVDProvider(
        client=client,
        mapper=mapper,
    )

    try:
        provider.scan(
            dependency,
        )
    except RuntimeError as exc:
        assert str(exc) == "NVD unavailable"
    else:
        raise AssertionError(
            "Expected RuntimeError to be raised",
        )

    client.query.assert_called_once_with(
        package_name="django",
    )

    mapper.map.assert_not_called()


def test_provider_uses_injected_client_and_mapper() -> None:
    client = Mock(
        spec=NVDClient,
    )

    mapper = Mock(
        spec=NVDMapper,
    )

    provider = NVDProvider(
        client=client,
        mapper=mapper,
    )

    assert provider.client is client
    assert provider.mapper is mapper


def test_provider_name_is_nvd() -> None:
    assert NVDProvider.name == Provider.NVD
