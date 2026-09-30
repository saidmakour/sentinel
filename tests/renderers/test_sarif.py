import json

import pytest

from sentinel.dto.scan_result import ScanResult
from sentinel.dto.scan_statistics import ScanStatistics
from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.dto.severity_summary import SeveritySummary
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity
from sentinel.renderers.sarif import SarifRenderer


def test_sarif_renderer_can_be_created() -> None:
    renderer = SarifRenderer()

    assert renderer is not None


def test_render_empty_result() -> None:
    renderer = SarifRenderer()

    result = ScanResult(
        dependencies=[],
        findings=[],
        statistics=ScanStatistics(
            dependency_count=0,
            finding_count=0,
            severity=SeveritySummary(),
            status={},
        ),
        dependency_summaries=[],
    )

    output = renderer.render(result)

    sarif = json.loads(output)

    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1


def _dependency() -> ScannedDependency:
    return ScannedDependency(
        name="requests",
        version="2.32.3",
        ecosystem=Ecosystem.PYPI,
        source="requirements.txt",
        priority=10,
    )


def _finding() -> VulnerabilityInfo:
    return VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.32.3",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2026-0001",
        aliases=["CVE-2026-0001"],
        sources=[Provider.OSV],
        summary="Test vulnerability",
        severity=Severity.HIGH,
        cvss=7.5,
    )


def test_render_sarif_report_with_finding() -> None:
    dependencies = [
        _dependency(),
    ]

    findings = [
        _finding(),
    ]

    renderer = SarifRenderer()

    result = ScanResult(
        dependencies=dependencies,
        findings=findings,
        statistics=ScanStatistics(
            dependency_count=10,
            finding_count=15,
            severity=SeveritySummary(),
            status={},
        ),
        dependency_summaries=[],
    )

    output = renderer.render(result)
    sarif = json.loads(output)
    # print(sarif)
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]

    assert run["tool"]["driver"]["name"] == "Sentinel"

    assert len(run["tool"]["driver"]["rules"]) == 1
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["id"] == "CVE-2026-0001"
    assert rule["name"] == "CVE-2026-0001"
    assert rule["shortDescription"]["text"] == "Test vulnerability"
    result = run["results"][0]
    assert len(run["results"]) == 1
    assert result["ruleId"] == "CVE-2026-0001"
    assert result["level"] == "error"
    assert result["message"]["text"] == "Test vulnerability"
    assert result["properties"]["dependency"] == "requests"
    assert result["properties"]["version"] == "2.32.3"

    assert result["properties"]["cvss"] == 7.5
    assert result["properties"]["sources"] == ["OSV"]
    assert result["properties"]["epss_score"] is None


@pytest.mark.parametrize(
    ("severity", "expected_level"),
    [
        ("CRITICAL", "error"),
        ("HIGH", "error"),
        ("MEDIUM", "warning"),
        ("LOW", "note"),
        ("UNKNOWN", "none"),
    ],
)
def test_severity_level(
    severity: str,
    expected_level: str,
) -> None:
    result = SarifRenderer._severity_level(
        severity,
    )

    assert result == expected_level
