from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity
from sentinel.providers.cache import ProviderCache


def make_dependency(version: str = "2.31.0") -> ScannedDependency:
    return ScannedDependency(
        name="requests",
        version=version,
        ecosystem=Ecosystem.PYPI,
        source="requirements.txt",
        priority=10,
    )


def make_finding() -> VulnerabilityInfo:
    return VulnerabilityInfo(
        identifier="CVE-1",
        aliases=["CVE-1"],
        dependency_name="requests",
        dependency_version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        sources=[Provider.OSV],
        severity=Severity.LOW,
        cvss=1.0,
        summary="Test",
    )


def test_get_returns_none_when_missing() -> None:
    cache = ProviderCache()

    assert (
        cache.get(
            Provider.OSV,
            make_dependency(),
        )
        is None
    )


def test_set_and_get() -> None:
    cache = ProviderCache()

    findings = [
        make_finding(),
    ]

    dependency = make_dependency()

    cache.set(
        Provider.OSV,
        dependency,
        findings,
    )

    assert (
        cache.get(
            Provider.OSV,
            dependency,
        )
        == findings
    )


def test_clear() -> None:
    cache = ProviderCache()

    dependency = make_dependency()

    cache.set(
        Provider.OSV,
        dependency,
        [
            make_finding(),
        ],
    )

    cache.clear()

    assert (
        cache.get(
            Provider.OSV,
            dependency,
        )
        is None
    )


def test_provider_is_part_of_cache_key() -> None:
    cache = ProviderCache()

    dependency = make_dependency()

    cache.set(
        Provider.OSV,
        dependency,
        [
            make_finding(),
        ],
    )

    assert (
        cache.get(
            Provider.NVD,
            dependency,
        )
        is None
    )
