from unittest.mock import MagicMock

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity
from sentinel.providers.github.client import GitHubAdvisoryClient
from sentinel.providers.github.mapper import GitHubAdvisoryMapper
from sentinel.providers.github.models import GitHubAdvisory
from sentinel.providers.github.parser import GitHubAdvisoryParser
from sentinel.providers.github.provider import GitHubAdvisoryProvider


def create_dependency() -> ScannedDependency:
    return ScannedDependency(
        name="requests",
        version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        source="requirements.txt",
    )


def create_advisory() -> GitHubAdvisory:
    return GitHubAdvisory(
        ghsa_id="GHSA-abcd-1234-efgh",
        summary="Test vulnerability",
        description="Test description",
        severity="high",
        cve_id="CVE-2026-1234",
        identifiers=[],
        vulnerabilities=[],
    )


def create_vulnerability() -> VulnerabilityInfo:
    return VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2026-1234",
        aliases=[
            "GHSA-abcd-1234-efgh",
            "CVE-2026-1234",
        ],
        sources=[Provider.GITHUB_ADVISORY],
        summary="Test vulnerability",
        severity=Severity.HIGH,
        cvss=None,
    )


def test_provider_name() -> None:
    provider = GitHubAdvisoryProvider()

    assert provider.name == Provider.GITHUB_ADVISORY


def test_scan() -> None:
    client = MagicMock(spec=GitHubAdvisoryClient)
    parser = MagicMock(spec=GitHubAdvisoryParser)
    mapper = MagicMock(spec=GitHubAdvisoryMapper)

    dependency = create_dependency()
    advisory_data = {
        "ghsa_id": "GHSA-abcd-1234-efgh",
    }
    advisory = create_advisory()
    vulnerability = create_vulnerability()

    client.query.return_value = [advisory_data]
    parser.parse.return_value = advisory
    mapper.map.return_value = [vulnerability]

    provider = GitHubAdvisoryProvider(
        client=client,
        parser=parser,
        mapper=mapper,
    )

    result = provider.scan(dependency)

    assert result == [vulnerability]

    client.query.assert_called_once_with(
        package_name="requests",
        version="2.31.0",
        ecosystem="pypi",
    )

    parser.parse.assert_called_once_with(
        advisory_data,
    )

    mapper.map.assert_called_once_with(
        dependency,
        [advisory],
    )


def test_scan_ignores_invalid_advisories() -> None:
    client = MagicMock(spec=GitHubAdvisoryClient)
    parser = MagicMock(spec=GitHubAdvisoryParser)
    mapper = MagicMock(spec=GitHubAdvisoryMapper)

    dependency = create_dependency()
    advisory_data = {
        "ghsa_id": "invalid",
    }
    advisory = create_advisory()
    vulnerability = create_vulnerability()

    client.query.return_value = [
        advisory_data,
        {"invalid": True},
    ]

    parser.parse.side_effect = [
        advisory,
        None,
    ]

    mapper.map.return_value = [vulnerability]

    provider = GitHubAdvisoryProvider(
        client=client,
        parser=parser,
        mapper=mapper,
    )

    result = provider.scan(dependency)

    assert result == [vulnerability]

    assert parser.parse.call_count == 2

    mapper.map.assert_called_once_with(
        dependency,
        [advisory],
    )


def test_scan_with_no_advisories() -> None:
    client = MagicMock(spec=GitHubAdvisoryClient)
    parser = MagicMock(spec=GitHubAdvisoryParser)
    mapper = MagicMock(spec=GitHubAdvisoryMapper)

    dependency = create_dependency()

    client.query.return_value = []
    mapper.map.return_value = []

    provider = GitHubAdvisoryProvider(
        client=client,
        parser=parser,
        mapper=mapper,
    )

    result = provider.scan(dependency)

    assert result == []

    parser.parse.assert_not_called()

    mapper.map.assert_called_once_with(
        dependency,
        [],
    )
