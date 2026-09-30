import json

from sentinel.dto.scan_result import ScanResult
from sentinel.dto.scan_statistics import ScanStatistics
from sentinel.dto.severity_summary import SeveritySummary
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity
from sentinel.enums.vulnerability_status import VulnerabilityStatus
from sentinel.renderers.json import JsonRenderer


def test_json_renderer_can_be_created() -> None:
    renderer = JsonRenderer()

    assert renderer is not None


def test_render_empty_findings() -> None:
    renderer = JsonRenderer()

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

    assert '"findings": []' in output
    assert '"finding_count": 0' in output


def test_render_finding() -> None:
    finding = VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.32.3",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2026-0001",
        aliases=["CVE-2026-0001", "GHSA-test"],
        sources=[Provider.OSV, Provider.NVD],
        summary="Test vulnerability",
        severity=Severity.HIGH,
        cvss=7.5,
        status=VulnerabilityStatus.OPEN,
        fixed_versions=["2.32.4"],
        known_exploited=True,
        epss_score=0.42,
        epss_percentile=0.75,
    )

    result = ScanResult(
        dependencies=[],
        findings=[finding],
        statistics=ScanStatistics(
            dependency_count=1,
            finding_count=1,
            severity=SeveritySummary(
                critical=0,
                high=1,
                medium=0,
                low=0,
                unknown=0,
            ),
            status={},
        ),
        dependency_summaries=[],
    )

    output = JsonRenderer().render(result)

    data = json.loads(output)

    assert data["statistics"]["dependency_count"] == 1
    assert data["statistics"]["finding_count"] == 1
    assert data["statistics"]["severity"]["high"] == 1

    assert len(data["findings"]) == 1

    finding_data = data["findings"][0]

    assert finding_data["dependency_name"] == "requests"
    assert finding_data["dependency_version"] == "2.32.3"
    assert finding_data["ecosystem"] == "PyPI"
    assert finding_data["identifier"] == "CVE-2026-0001"
    assert finding_data["aliases"] == [
        "CVE-2026-0001",
        "GHSA-test",
    ]
    assert finding_data["severity"] == "HIGH"
    assert finding_data["cvss"] == 7.5
    assert finding_data["status"] == "OPEN"
    assert finding_data["fixed_versions"] == ["2.32.4"]
    assert finding_data["known_exploited"] is True
    assert finding_data["epss_score"] == 0.42
    assert finding_data["epss_percentile"] == 0.75
