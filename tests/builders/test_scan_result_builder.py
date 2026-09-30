from sentinel.builders.scan_result_builder import ScanResultBuilder
from sentinel.dto.remediation_info import RemediationInfo
from sentinel.dto.remediation_info import RemediationRule
from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.enums.security_status import SecurityStatus
from sentinel.enums.severity import Severity
from sentinel.enums.vulnerability_status import VulnerabilityStatus


def _dependency() -> ScannedDependency:
    return ScannedDependency(
        name="requests",
        version="2.32.3",
        ecosystem=Ecosystem.PYPI,
        source="requirements.txt",
        priority=10,
    )


def _finding(
    severity: Severity,
) -> VulnerabilityInfo:
    return VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.32.3",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2026-0001",
        aliases=[],
        sources=[Provider.OSV],
        summary="Test vulnerability",
        severity=severity,
        cvss=7.5,
    )


def test_scan_result_builder_can_be_created() -> None:
    builder = ScanResultBuilder()

    assert builder is not None


def test_build_returns_scan_result() -> None:
    builder = ScanResultBuilder()

    result = builder.build(
        dependencies=[
            _dependency(),
        ],
        findings=[
            _finding(Severity.HIGH),
        ],
    )

    assert result is not None


def test_build_keeps_dependencies() -> None:
    builder = ScanResultBuilder()

    dependencies = [
        _dependency(),
    ]

    result = builder.build(
        dependencies=dependencies,
        findings=[],
    )

    assert result.dependencies == dependencies


def test_build_keeps_findings() -> None:
    builder = ScanResultBuilder()

    findings = [
        _finding(Severity.CRITICAL),
    ]

    result = builder.build(
        dependencies=[],
        findings=findings,
    )

    assert result.findings == findings


def test_build_calculates_statistics() -> None:
    builder = ScanResultBuilder()

    result = builder.build(
        dependencies=[
            _dependency(),
            _dependency(),
        ],
        findings=[
            _finding(Severity.CRITICAL),
            _finding(Severity.HIGH),
            _finding(Severity.HIGH),
            _finding(Severity.LOW),
            _finding(Severity.UNKNOWN),
        ],
    )

    assert result.statistics.dependency_count == 2
    assert result.statistics.finding_count == 5


def test_build_calculates_severity_summary() -> None:
    builder = ScanResultBuilder()

    result = builder.build(
        dependencies=[],
        findings=[
            _finding(Severity.CRITICAL),
            _finding(Severity.HIGH),
            _finding(Severity.HIGH),
            _finding(Severity.MEDIUM),
            _finding(Severity.LOW),
            _finding(Severity.UNKNOWN),
        ],
    )

    severity = result.statistics.severity

    assert severity.critical == 1
    assert severity.high == 2
    assert severity.medium == 1
    assert severity.low == 1
    assert severity.unknown == 1
    assert severity.total == 6


def test_build_scan_result():

    builder = ScanResultBuilder()

    dependencies = [
        ScannedDependency(
            name="requests",
            version="2.31.0",
            ecosystem=Ecosystem.PYPI,
            source="requirements.txt",
        )
    ]

    findings = [
        VulnerabilityInfo(
            dependency_name="requests",
            dependency_version="2.31.0",
            ecosystem=Ecosystem.PYPI,
            identifier="CVE-1",
            aliases=["CVE-1"],
            sources=[],
            summary="test",
            severity=Severity.HIGH,
            cvss=7.5,
        )
    ]

    result = builder.build(
        dependencies,
        findings,
    )

    assert len(result.dependencies) == 1
    assert len(result.findings) == 1


def create_finding(
    *,
    identifier: str = "CVE-2026-0001",
    severity: Severity = Severity.HIGH,
    status: VulnerabilityStatus = VulnerabilityStatus.UNKNOWN,
) -> VulnerabilityInfo:
    return VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.32.3",
        ecosystem=Ecosystem.PYPI,
        identifier=identifier,
        aliases=[],
        sources=[Provider.OSV],
        summary="Test vulnerability",
        severity=severity,
        cvss=7.5,
        status=status,
    )


def test_build_counts_vulnerability_statuses() -> None:
    builder = ScanResultBuilder()

    findings = [
        create_finding(
            status=VulnerabilityStatus.OPEN,
        ),
        create_finding(
            identifier="CVE-2026-0002",
            status=VulnerabilityStatus.OPEN,
        ),
        create_finding(
            identifier="CVE-2026-0003",
            status=VulnerabilityStatus.RESOLVED,
        ),
        create_finding(
            identifier="CVE-2026-0004",
            status=VulnerabilityStatus.UNKNOWN,
        ),
    ]

    result = builder.build(
        dependencies=[],
        findings=findings,
    )

    assert result.statistics.status == {
        "OPEN": 2,
        "RESOLVED": 1,
        "UNKNOWN": 1,
    }


def test_build_counts_unknown_severity() -> None:
    builder = ScanResultBuilder()

    findings = [
        create_finding(
            severity=Severity.UNKNOWN,
        ),
    ]

    result = builder.build(
        dependencies=[],
        findings=findings,
    )

    assert result.statistics.severity.unknown == 1


def test_build_creates_dependency_security_summary() -> None:
    builder = ScanResultBuilder()

    finding = VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2024-0001",
        aliases=[],
        sources=[],
        summary="Security vulnerability",
        severity=Severity.HIGH,
        cvss=8.0,
        status=VulnerabilityStatus.OPEN,
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    introduced="2.0.0",
                    fixed="2.32.0",
                    affected_range="<2.32.0",
                ),
            ],
        ),
        fixed_versions=["2.32.0"],
    )

    result = builder.build(
        dependencies=[
            ScannedDependency(
                name="requests",
                version="2.31.0",
                ecosystem=Ecosystem.PYPI,
                source="requirements.txt",
            ),
        ],
        findings=[finding],
    )

    assert len(result.dependency_summaries) == 1

    summary = result.dependency_summaries[0]

    assert summary.dependency_name == "requests"
    assert summary.installed_version == "2.31.0"
    assert summary.security_status == SecurityStatus.AT_RISK
    assert summary.open_finding_count == 1
    assert summary.recommended_version == "2.32.0"
