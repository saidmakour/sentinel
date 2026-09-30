from sentinel.dto.scan_result import ScanResult
from sentinel.dto.scan_statistics import ScanStatistics
from sentinel.dto.severity_summary import SeveritySummary
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity
from sentinel.renderers.markdown import MarkdownRenderer


def test_markdown_renderer_can_be_created() -> None:
    renderer = MarkdownRenderer()

    assert renderer is not None


def test_render_empty_findings() -> None:
    renderer = MarkdownRenderer()

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

    assert "# Sentinel Report" in output
    assert "No vulnerabilities found." in output
    assert "Dependencies: 0" in output


def test_render_finding() -> None:
    renderer = MarkdownRenderer()

    finding = VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2025-0001",
        aliases=["CVE-2025-0001"],
        sources=[Provider.OSV],
        severity=Severity.HIGH,
        cvss=9.8,
        summary="Example vulnerability",
    )

    result = ScanResult(
        dependencies=[],
        findings=[
            finding,
        ],
        statistics=ScanStatistics(
            dependency_count=1,
            finding_count=1,
            severity=SeveritySummary(
                high=1,
            ),
            status={},
        ),
        dependency_summaries=[],
    )

    output = renderer.render(result)

    assert "# Sentinel Report" in output
    assert "requests" in output
    assert "CVE-2025-0001" in output
    assert "HIGH" in output
    assert "Example vulnerability" in output
    assert "High: 1" in output
