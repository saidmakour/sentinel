import pytest

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity
from sentinel.providers.nvd.mapper import NVDMapper
from sentinel.providers.nvd.models import NVDMetric
from sentinel.providers.nvd.models import NVDResponse
from sentinel.providers.nvd.models import NVDVersionRange
from sentinel.providers.nvd.models import NVDVulnerability


def test_map_single_vulnerability() -> None:
    dependency = ScannedDependency(
        name="requests",
        version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        source="requirements.txt",
        priority=10,
    )

    response = NVDResponse(
        vulnerabilities=[
            NVDVulnerability(
                identifier="CVE-2025-0001",
                aliases=["CVE-2025-0001"],
                summary="Test vulnerability",
                metric=NVDMetric(
                    score=9.8,
                ),
                configurations=[
                    NVDVersionRange(
                        criteria="cpe:2.3:a:python:requests:*",
                    ),
                ],
            )
        ]
    )

    mapper = NVDMapper()

    results = mapper.map(
        dependency,
        response,
    )

    assert len(results) == 1

    result = results[0]

    assert result.identifier == "CVE-2025-0001"
    assert result.dependency_name == "requests"
    assert result.dependency_version == "2.31.0"
    assert result.ecosystem == Ecosystem.PYPI
    assert result.sources == [Provider.NVD]
    assert result.cvss == 9.8
    assert result.severity == Severity.CRITICAL
    assert result.summary == "Test vulnerability"


def test_map_empty_response() -> None:
    dependency = ScannedDependency(
        name="requests",
        version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        source="requirements.txt",
        priority=10,
    )

    response = NVDResponse(
        vulnerabilities=[],
    )

    mapper = NVDMapper()

    results = mapper.map(
        dependency,
        response,
    )

    assert results == []


def test_map_unknown_severity() -> None:
    dependency = ScannedDependency(
        name="requests",
        version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        source="requirements.txt",
        priority=10,
    )

    response = NVDResponse(
        vulnerabilities=[
            NVDVulnerability(
                identifier="CVE-2025-0002",
                aliases=["CVE-2025-0002"],
                summary="No CVSS available",
                metric=NVDMetric(
                    score=None,
                ),
                configurations=[
                    NVDVersionRange(
                        criteria="cpe:2.3:a:python:requests:*",
                    ),
                ],
            )
        ]
    )

    mapper = NVDMapper()

    results = mapper.map(
        dependency,
        response,
    )

    assert len(results) == 1

    result = results[0]

    assert result.identifier == "CVE-2025-0002"
    assert result.cvss is None
    assert result.severity == Severity.UNKNOWN
    assert result.summary == "No CVSS available"


def test_pypi_click_does_not_match_click_project_cpe() -> None:
    dependency = ScannedDependency(
        name="click",
        version="8.4.2",
        ecosystem=Ecosystem.PYPI,
        source="uv.lock",
    )

    vulnerability = NVDVulnerability(
        identifier="CVE-2015-8768",
        aliases=[],
        summary="Ubuntu click vulnerability",
        metric=NVDMetric(score=9.8),
        configurations=[
            NVDVersionRange(
                criteria=("cpe:2.3:a:click_project:click:-:*:*:*:*:*:*:*"),
            ),
        ],
    )

    response = NVDResponse(
        vulnerabilities=[vulnerability],
    )

    mapper = NVDMapper()

    result = mapper.map(
        dependency,
        response,
    )

    assert result == []


@pytest.mark.parametrize(
    ("ecosystem", "vendor", "target_software", "expected"),
    [
        (Ecosystem.PYPI, "python", None, True),
        (Ecosystem.PYPI, "pypa", None, True),
        (Ecosystem.PYPI, "click_project", None, False),
        (Ecosystem.NPM, "npmjs", None, True),
        (Ecosystem.NPM, "nodejs", None, True),
        (Ecosystem.NPM, "some_project", "node.js", True),
        (Ecosystem.NPM, "some_project", "python", False),
        (Ecosystem.COMPOSER, "some_project", "php", True),
        (Ecosystem.COMPOSER, "some_project", "composer", True),
        (Ecosystem.COMPOSER, "php", None, False),
        (Ecosystem.MAVEN, "some_project", "java", True),
        (Ecosystem.MAVEN, "some_project", "maven", True),
        (Ecosystem.MAVEN, "some_project", "python", False),
        (Ecosystem.GOLANG, "golang", None, True),
        (Ecosystem.GOLANG, "some_project", "go", True),
        (Ecosystem.GOLANG, "some_project", "golang", True),
        (Ecosystem.GOLANG, "some_project", "python", False),
        (Ecosystem.RUBYGEMS, "ruby-lang", None, True),
        (Ecosystem.RUBYGEMS, "some_project", "ruby", True),
        (Ecosystem.RUBYGEMS, "some_project", "python", False),
    ],
)
def test_matches_ecosystem(
    ecosystem: Ecosystem,
    vendor: str,
    target_software: str | None,
    expected: bool,
) -> None:
    mapper = NVDMapper()

    assert (
        mapper._matches_ecosystem(
            ecosystem,
            vendor,
            target_software,
        )
        is expected
    )


def test_pypi_click_does_not_match_click_project() -> None:
    mapper = NVDMapper()

    dependency = ScannedDependency(
        name="click",
        version="8.4.2",
        ecosystem=Ecosystem.PYPI,
        source="uv.lock",
    )

    configuration = NVDVersionRange(
        criteria=("cpe:2.3:a:click_project:click:*:*:*:*:*:*:*:*"),
    )

    vulnerability = NVDVulnerability(
        identifier="CVE-2015-8768",
        aliases=[],
        summary="Test",
        metric=NVDMetric(score=3.0),
        configurations=[configuration],
    )

    result = mapper.map(
        dependency,
        NVDResponse(
            vulnerabilities=[vulnerability],
        ),
    )

    assert result == []


def test_pypi_click_matches_python_vendor() -> None:
    mapper = NVDMapper()

    dependency = ScannedDependency(
        name="click",
        version="8.4.2",
        ecosystem=Ecosystem.PYPI,
        source="uv.lock",
    )

    configuration = NVDVersionRange(
        criteria=("cpe:2.3:a:python:click:*:*:*:*:*:*:*:*"),
    )

    vulnerability = NVDVulnerability(
        identifier="CVE-TEST",
        aliases=[],
        summary="Test",
        metric=NVDMetric(score=3.0),
        configurations=[configuration],
    )

    result = mapper.map(
        dependency,
        NVDResponse(
            vulnerabilities=[vulnerability],
        ),
    )

    assert len(result) == 1
    assert result[0].identifier == "CVE-TEST"


def test_nvd_version_range_extracts_vendor() -> None:
    config = NVDVersionRange(
        criteria=("cpe:2.3:a:python:click:8.1.7:*:*:*:*:*:*:*"),
    )

    assert config.vendor == "python"


def test_nvd_version_range_extracts_product() -> None:
    config = NVDVersionRange(
        criteria=("cpe:2.3:a:python:click:8.1.7:*:*:*:*:*:*:*"),
    )

    assert config.product == "click"


def test_nvd_version_range_returns_none_for_wildcard_target_software() -> None:
    config = NVDVersionRange(
        criteria=("cpe:2.3:a:python:click:8.1.7:*:*:*:*:*:*:*"),
    )

    assert config.target_software is None


def test_nvd_version_range_normalizes_vendor_and_product() -> None:
    config = NVDVersionRange(
        criteria=("cpe:2.3:a:Python:Click:8.1.7:*:*:*:*:*:*:*"),
    )

    assert config.vendor == "python"
    assert config.product == "click"
