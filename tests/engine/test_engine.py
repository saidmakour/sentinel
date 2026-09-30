from pathlib import Path
from unittest.mock import MagicMock

from sentinel.dto.scan_result import ScanResult
from sentinel.dto.scan_statistics import ScanStatistics
from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.dto.severity_summary import SeveritySummary
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.engine.engine import SentinelEngine
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity
from sentinel.enums.vulnerability_status import VulnerabilityStatus
from sentinel.profiles.default import DefaultProfile
from sentinel.providers.base import BaseProvider


class DummyScanner:
    def __init__(self) -> None:
        self.called = False
        self.path: Path | None = None

    def scan(
        self,
        path: Path,
    ) -> list[ScannedDependency]:
        self.called = True
        self.path = path

        return [
            ScannedDependency(
                name="requests",
                version="2.32.3",
                ecosystem=Ecosystem.PYPI,
                source="requirements.txt",
                priority=10,
            )
        ]


class DummyScannerFactory:
    def __init__(self) -> None:
        self.language: str | None = None
        self.scanner = DummyScanner()

    def create(
        self,
        language: str,
    ) -> DummyScanner:
        self.language = language
        return self.scanner


class DummyProvider(BaseProvider):
    name = Provider.OSV

    def scan(
        self,
        dependency: ScannedDependency,
    ) -> list[VulnerabilityInfo]:
        return []


class DummyProviderRegistry:
    def __init__(self):
        self.providers = None

    def create(self, providers):
        self.providers = providers
        return []


class DummyProviderExecutor:
    def __init__(self) -> None:
        self.called = False
        self.dependency: ScannedDependency | None = None
        self.providers: list[BaseProvider] | None = None

    def execute(
        self,
        dependency: ScannedDependency,
        providers: list[BaseProvider],
    ) -> list[VulnerabilityInfo]:
        self.called = True
        self.dependency = dependency
        self.providers = providers

        return [
            VulnerabilityInfo(
                identifier="CVE-2026-0001",
                aliases=["CVE-2026-0001"],
                dependency_name=dependency.name,
                dependency_version=dependency.version,
                ecosystem=Ecosystem.PYPI,
                sources=[Provider.OSV],
                severity=Severity.MEDIUM,
                cvss=6.5,
                summary="Short vulnerability",
            ),
            VulnerabilityInfo(
                identifier="CVE-2026-0001",
                aliases=["CVE-2026-0001"],
                dependency_name=dependency.name,
                dependency_version=dependency.version,
                ecosystem=Ecosystem.PYPI,
                sources=[Provider.NVD],
                severity=Severity.CRITICAL,
                cvss=9.8,
                summary="Longer vulnerability description",
            ),
        ]


class DummyScanResultBuilder:
    def __init__(self) -> None:
        self.called = False
        self.dependencies: list[ScannedDependency] | None = None
        self.findings: list[VulnerabilityInfo] | None = None

    def build(
        self,
        dependencies: list[ScannedDependency],
        findings: list[VulnerabilityInfo],
    ) -> ScanResult:

        self.called = True
        self.dependencies = dependencies
        self.findings = findings

        return ScanResult(
            dependencies=dependencies,
            findings=findings,
            statistics=ScanStatistics(
                dependency_count=len(dependencies),
                finding_count=len(findings),
                severity=SeveritySummary(),
                status={},
            ),
            dependency_summaries=[],
        )


class DummyFindingNormalizer:
    def __init__(self) -> None:
        self.called = False

    def normalize(
        self,
        findings: list[VulnerabilityInfo],
    ) -> list[VulnerabilityInfo]:

        self.called = True

        return findings


class DummyEnricherRegistry:
    def __init__(self) -> None:
        self.enrichers = None

    def create(self, enrichers):
        self.enrichers = enrichers
        return ["dummy-enricher"]


class DummyEnricherExecutor:
    def __init__(self) -> None:
        self.called = False
        self.findings = None
        self.enrichers = None

    def execute(
        self,
        findings: list[VulnerabilityInfo],
        enrichers,
    ) -> list[VulnerabilityInfo]:
        self.called = True
        self.findings = findings
        self.enrichers = enrichers

        for finding in findings:
            finding.vulncheck_known_exploited = True

        return findings


class DummyVulnerabilityStatusService:
    def __init__(self) -> None:
        self.called = False
        self.findings: list[VulnerabilityInfo] | None = None

    def apply(
        self,
        finding: VulnerabilityInfo,
    ) -> VulnerabilityInfo:

        self.called = True

        finding.status = VulnerabilityStatus.UNKNOWN

        return finding


def test_engine_can_be_created() -> None:
    engine = SentinelEngine()

    assert engine is not None


def test_run_calls_scanner_factory() -> None:
    scanner_factory = DummyScannerFactory()
    provider_registry = DummyProviderRegistry()
    provider_executor = DummyProviderExecutor()

    engine = SentinelEngine(
        scanner_factory=scanner_factory,
        provider_registry=provider_registry,
        provider_executor=provider_executor,
    )

    engine.run(
        language="python",
        path=Path("."),
        profile=DefaultProfile(),
    )

    assert scanner_factory.language == "python"


def test_run_calls_scanner() -> None:
    scanner_factory = DummyScannerFactory()
    provider_registry = DummyProviderRegistry()
    provider_executor = DummyProviderExecutor()

    engine = SentinelEngine(
        scanner_factory=scanner_factory,
        provider_registry=provider_registry,
        provider_executor=provider_executor,
    )

    path = Path(".")

    engine.run(
        language="python",
        path=path,
        profile=DefaultProfile(),
    )

    assert scanner_factory.scanner.called
    assert scanner_factory.scanner.path == path


def test_run_calls_provider_executor(
    default_profile,
) -> None:
    scanner_factory = DummyScannerFactory()
    provider_registry = DummyProviderRegistry()
    provider_executor = DummyProviderExecutor()

    engine = SentinelEngine(
        scanner_factory=scanner_factory,
        provider_registry=provider_registry,
        provider_executor=provider_executor,
    )

    dependencies = engine.scan_dependencies(
        language="python",
        path=Path("."),
    )

    engine.find_vulnerabilities(
        dependencies,
        default_profile,
    )

    assert provider_executor.called
    assert provider_executor.dependency is not None
    assert provider_executor.dependency.name == "requests"
    assert provider_registry.providers == [
        Provider.OSV,
        Provider.NVD,
    ]


def test_run_returns_findings(
    default_profile,
) -> None:
    scanner_factory = DummyScannerFactory()
    provider_registry = DummyProviderRegistry()
    provider_executor = DummyProviderExecutor()

    engine = SentinelEngine(
        scanner_factory=scanner_factory,
        provider_registry=provider_registry,
        provider_executor=provider_executor,
    )

    dependencies = engine.scan_dependencies(
        language="python",
        path=Path("."),
    )

    findings = engine.find_vulnerabilities(
        dependencies,
        default_profile,
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.identifier == "CVE-2026-0001"
    assert finding.dependency_name == "requests"
    assert finding.dependency_version == "2.32.3"

    assert finding.sources == [
        Provider.OSV,
        Provider.NVD,
    ]

    assert finding.severity == Severity.CRITICAL
    assert finding.cvss == 9.8
    assert finding.summary == "Longer vulnerability description"


def test_run_calls_provider_regsitry(
    default_profile,
) -> None:
    scanner_factory = DummyScannerFactory()
    provider_registry = DummyProviderRegistry()
    provider_executor = DummyProviderExecutor()

    engine = SentinelEngine(
        scanner_factory=scanner_factory,
        provider_registry=provider_registry,
        provider_executor=provider_executor,
    )

    dependencies = engine.scan_dependencies(
        language="python",
        path=Path("."),
    )

    engine.find_vulnerabilities(
        dependencies,
        default_profile,
    )

    assert provider_registry.providers == [
        Provider.OSV,
        Provider.NVD,
    ]


def test_run_executes_full_pipeline() -> None:
    scanner_factory = DummyScannerFactory()
    provider_registry = DummyProviderRegistry()
    provider_executor = DummyProviderExecutor()

    engine = SentinelEngine(
        scanner_factory=scanner_factory,
        provider_registry=provider_registry,
        provider_executor=provider_executor,
    )

    result = engine.run(
        language="python",
        path=Path("."),
        profile=DefaultProfile(),
    )

    assert len(result.findings) == 1
    assert result.findings[0].identifier == "CVE-2026-0001"

    assert result.statistics.dependency_count == 1
    assert result.statistics.finding_count == 1


def test_run_merges_duplicate_findings() -> None:
    scanner_factory = DummyScannerFactory()
    provider_registry = DummyProviderRegistry()
    provider_executor = DummyProviderExecutor()

    engine = SentinelEngine(
        scanner_factory=scanner_factory,
        provider_registry=provider_registry,
        provider_executor=provider_executor,
    )

    result = engine.run(
        language="python",
        path=Path("."),
        profile=DefaultProfile(),
    )

    assert len(result.findings) == 1


def test_run_calls_scan_result_builder() -> None:
    scanner_factory = DummyScannerFactory()
    provider_registry = DummyProviderRegistry()
    provider_executor = DummyProviderExecutor()

    scan_result_builder = DummyScanResultBuilder()

    engine = SentinelEngine(
        scanner_factory=scanner_factory,
        provider_registry=provider_registry,
        provider_executor=provider_executor,
        scan_result_builder=scan_result_builder,
    )

    result = engine.run(
        language="python",
        path=Path("."),
        profile=DefaultProfile(),
    )

    assert scan_result_builder.called
    assert result.findings


def test_run_calls_finding_normalizer(
    default_profile,
) -> None:

    scanner_factory = DummyScannerFactory()
    provider_registry = DummyProviderRegistry()
    provider_executor = DummyProviderExecutor()
    normalizer = DummyFindingNormalizer()

    engine = SentinelEngine(
        scanner_factory=scanner_factory,
        provider_registry=provider_registry,
        provider_executor=provider_executor,
        finding_normalizer=normalizer,
    )

    engine.run(
        language="python",
        path=Path("."),
        profile=default_profile,
    )

    assert normalizer.called


def test_run_calls_vulnerability_status_service(
    default_profile,
) -> None:

    scanner_factory = DummyScannerFactory()
    provider_registry = DummyProviderRegistry()
    provider_executor = DummyProviderExecutor()

    status_service = DummyVulnerabilityStatusService()

    engine = SentinelEngine(
        scanner_factory=scanner_factory,
        provider_registry=provider_registry,
        provider_executor=provider_executor,
        vulnerability_status_service=status_service,
    )

    engine.run(
        language="python",
        path=Path("."),
        profile=default_profile,
    )

    assert status_service.called


def test_apply_vulnerability_status():
    status_service = MagicMock()

    finding1 = VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.32.3",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2026-0001",
        aliases=[],
        sources=[Provider.OSV],
        severity=Severity.HIGH,
        cvss=7.5,
        summary="Test vulnerability",
    )

    finding2 = VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.32.3",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2026-0002",
        aliases=[],
        sources=[Provider.OSV],
        severity=Severity.MEDIUM,
        cvss=5.5,
        summary="Test vulnerability",
    )

    status_service.apply.side_effect = [
        finding1,
        finding2,
    ]

    engine = SentinelEngine(
        vulnerability_status_service=status_service,
    )

    result = engine._apply_vulnerability_status(
        [finding1, finding2],
    )

    assert result == [
        finding1,
        finding2,
    ]

    assert status_service.apply.call_count == 2


def test_run_calls_enricher_executor(
    default_profile,
) -> None:
    scanner_factory = DummyScannerFactory()
    provider_registry = DummyProviderRegistry()
    provider_executor = DummyProviderExecutor()

    enricher_registry = DummyEnricherRegistry()
    enricher_executor = DummyEnricherExecutor()

    engine = SentinelEngine(
        scanner_factory=scanner_factory,
        provider_registry=provider_registry,
        provider_executor=provider_executor,
        enricher_registry=enricher_registry,
        enricher_executor=enricher_executor,
    )

    dependencies = engine.scan_dependencies(
        language="python",
        path=Path("."),
    )

    findings = engine.find_vulnerabilities(
        dependencies,
        default_profile,
    )

    assert enricher_executor.called
    assert enricher_executor.findings == findings
    assert enricher_executor.enrichers == [
        "dummy-enricher",
    ]

    assert all(finding.vulncheck_known_exploited for finding in findings)
