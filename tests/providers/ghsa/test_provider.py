from unittest.mock import MagicMock

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.providers.ghsa.models import GHSAResponse
from sentinel.providers.ghsa.provider import GHSAProvider


def create_dependency() -> ScannedDependency:
    return ScannedDependency(
        name="requests",
        version="2.32.0",
        ecosystem=Ecosystem.PYPI,
        source="requirements.txt",
    )


def test_provider_has_expected_name() -> None:
    assert GHSAProvider.name == Provider.GHSA


def test_provider_can_be_created() -> None:
    provider = GHSAProvider()

    assert provider is not None


def test_provider_calls_client() -> None:
    client = MagicMock()
    mapper = MagicMock()

    response = GHSAResponse(
        vulnerabilities=[],
    )

    client.query.return_value = response
    mapper.map.return_value = []

    provider = GHSAProvider(
        client=client,
        mapper=mapper,
    )

    dependency = create_dependency()

    provider.scan(
        dependency,
    )

    client.query.assert_called_once_with(
        package_name="requests",
        ecosystem=Ecosystem.PYPI,
    )


def test_provider_calls_mapper() -> None:
    client = MagicMock()
    mapper = MagicMock()

    response = GHSAResponse(
        vulnerabilities=[],
    )

    client.query.return_value = response
    mapper.map.return_value = []

    provider = GHSAProvider(
        client=client,
        mapper=mapper,
    )

    dependency = create_dependency()

    provider.scan(
        dependency,
    )

    mapper.map.assert_called_once_with(
        dependency,
        response,
    )


def test_provider_returns_mapper_result() -> None:
    client = MagicMock()
    mapper = MagicMock()

    response = GHSAResponse(
        vulnerabilities=[],
    )

    findings = [
        MagicMock(),
    ]

    client.query.return_value = response
    mapper.map.return_value = findings

    provider = GHSAProvider(
        client=client,
        mapper=mapper,
    )

    dependency = create_dependency()

    result = provider.scan(
        dependency,
    )

    assert result == findings
