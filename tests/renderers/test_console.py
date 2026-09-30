from sentinel.dto.scan_result import ScanResult
from sentinel.dto.scan_statistics import ScanStatistics
from sentinel.dto.severity_summary import SeveritySummary
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity
from sentinel.renderers.console import ConsoleRenderer


def test_console_renderer_can_be_created() -> None:
    renderer = ConsoleRenderer()

    assert renderer is not None


def test_render_empty_findings() -> None:
    renderer = ConsoleRenderer()

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

    assert "No vulnerabilities found." in output


def test_console_renderer_vulnerability_info() -> None:

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

    renderer = ConsoleRenderer()

    output = renderer.render(result)

    assert "requests" in output
    assert "CVE-2025-0001" in output
    assert "HIGH" in output
    assert "Example vulnerability" in output
    assert "Findings" in output
