from threading import Event
from unittest.mock import Mock

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity
from sentinel.providers.base import BaseProvider
from sentinel.providers.cache import ProviderCache
from sentinel.providers.executor import ProviderExecutor


class DummyProvider(BaseProvider):
    def __init__(
        self,
        provider: Provider,
        identifier: str,
        aliases: list[str],
    ) -> None:
        self.name = provider
        self.identifier = identifier
        self.aliases = aliases

    def scan(
        self,
        dependency: ScannedDependency,
    ) -> list[VulnerabilityInfo]:
        return [
            VulnerabilityInfo(
                identifier=self.identifier,
                aliases=self.aliases,
                dependency_name=dependency.name,
                dependency_version=dependency.version,
                ecosystem=Ecosystem.PYPI,
                sources=[self.name],
                severity=Severity.LOW,
                cvss=1.0,
                summary="Test",
            )
        ]


class EmptyProvider(BaseProvider):
    name = Provider.OSV

    def scan(
        self,
        dependency: ScannedDependency,
    ) -> list[VulnerabilityInfo]:
        return []


class FailingProvider(BaseProvider):
    name = Provider.NVD

    def scan(
        self,
        dependency: ScannedDependency,
    ) -> list[VulnerabilityInfo]:
        raise RuntimeError("Boom")


class DummyProviderExecutor:
    def __init__(self) -> None:
        self.called = False
        self.dependency = None
        self.providers = None

    def execute(
        self,
        dependency,
        providers,
    ):
        self.called = True
        self.dependency = dependency
        self.providers = providers

        return [
            VulnerabilityInfo(
                identifier="CVE-1",
                aliases=["CVE-1"],
                dependency_name=dependency.name,
                dependency_version=dependency.version,
                ecosystem=Ecosystem.PYPI,
                sources=[Provider.OSV],
                severity=Severity.LOW,
                cvss=1.0,
                summary="Test",
            )
        ]


def make_dependency() -> ScannedDependency:
    return ScannedDependency(
        name="requests",
        version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        source="requirements.txt",
        priority=10,
    )


def test_execute_returns_all_findings() -> None:
    executor = ProviderExecutor()

    findings = executor.execute(
        make_dependency(),
        [
            DummyProvider(
                Provider.OSV,
                "CVE-2025-0001",
                ["CVE-2025-0001"],
            ),
            DummyProvider(
                Provider.NVD,
                "CVE-2025-0002",
                ["CVE-2025-0002"],
            ),
        ],
    )

    assert len(findings) == 2

    assert {finding.identifier for finding in findings} == {
        "CVE-2025-0001",
        "CVE-2025-0002",
    }


def test_execute_with_empty_provider() -> None:
    executor = ProviderExecutor()

    findings = executor.execute(
        make_dependency(),
        [
            EmptyProvider(),
        ],
    )

    assert findings == []


def test_execute_with_no_provider() -> None:
    executor = ProviderExecutor()

    findings = executor.execute(
        make_dependency(),
        [],
    )

    assert findings == []


def test_execute_ignores_provider_exception() -> None:
    executor = ProviderExecutor()

    findings = executor.execute(
        make_dependency(),
        [
            DummyProvider(
                Provider.OSV,
                "CVE-1",
                ["CVE-1"],
            ),
            FailingProvider(),
            DummyProvider(
                Provider.GHSA,
                "CVE-2",
                [
                    "CVE-2",
                ],
            ),
        ],
    )

    assert len(findings) == 2

    assert {finding.identifier for finding in findings} == {
        "CVE-1",
        "CVE-2",
    }


def test_execute_uses_cache() -> None:

    provider = DummyProvider(
        Provider.OSV,
        "CVE-2025-0001",
        ["CVE-2025-0001"],
    )

    executor = ProviderExecutor()

    dependency = make_dependency()

    first = executor.execute(
        dependency,
        [provider],
    )

    second = executor.execute(
        dependency,
        [provider],
    )

    assert first == second


class CountingProviderEmpty(BaseProvider):
    name = Provider.OSV

    def __init__(self) -> None:
        self.calls = 0

    def scan(
        self,
        dependency: ScannedDependency,
    ) -> list[VulnerabilityInfo]:

        self.calls += 1

        return []


def test_execute_cache_avoids_duplicate_calls() -> None:

    provider = CountingProviderEmpty()
    executor = ProviderExecutor()

    dependency = make_dependency()

    executor.execute(
        dependency,
        [provider],
    )

    executor.execute(
        dependency,
        [provider],
    )

    assert provider.calls == 1


class CountingProvider(BaseProvider):
    name = Provider.OSV

    def __init__(self) -> None:
        self.calls = 0

    def scan(
        self,
        dependency: ScannedDependency,
    ) -> list[VulnerabilityInfo]:

        self.calls += 1

        return [
            VulnerabilityInfo(
                identifier=f"CVE-{dependency.version}",
                aliases=[f"CVE-{dependency.version}"],
                dependency_name=dependency.name,
                dependency_version=dependency.version,
                ecosystem=Ecosystem.PYPI,
                sources=[self.name],
                severity=Severity.LOW,
                cvss=1.0,
                summary="Test",
            )
        ]


def test_cache_isolated_by_version() -> None:
    provider = CountingProvider()

    executor = ProviderExecutor()

    dependency_v1 = ScannedDependency(
        name="requests",
        version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        source="requirements.txt",
        priority=10,
    )

    dependency_v2 = ScannedDependency(
        name="requests",
        version="2.32.0",
        ecosystem=Ecosystem.PYPI,
        source="requirements.txt",
        priority=10,
    )

    executor.execute(
        dependency_v1,
        [provider],
    )

    executor.execute(
        dependency_v2,
        [provider],
    )

    assert provider.calls == 2


class BlockingProvider(BaseProvider):
    def __init__(
        self,
        provider: Provider,
        started: Event,
        release: Event,
    ) -> None:
        self.name = provider
        self.started = started
        self.release = release

    def scan(
        self,
        dependency: ScannedDependency,
    ) -> list[VulnerabilityInfo]:

        self.started.set()

        self.release.wait(
            timeout=2,
        )

        return []


def test_execute_runs_providers_in_parallel() -> None:
    started_a = Event()
    started_b = Event()

    release = Event()

    executor = ProviderExecutor()

    providers = [
        BlockingProvider(
            Provider.OSV,
            started_a,
            release,
        ),
        BlockingProvider(
            Provider.NVD,
            started_b,
            release,
        ),
    ]

    dependency = make_dependency()

    import threading

    thread = threading.Thread(
        target=executor.execute,
        args=(
            dependency,
            providers,
        ),
    )

    thread.start()

    assert started_a.wait(timeout=1)
    assert started_b.wait(timeout=1)

    release.set()

    thread.join(timeout=2)

    assert not thread.is_alive()


def make_dependency_2() -> ScannedDependency:
    return ScannedDependency(
        name="django",
        version="5.2.0",
        ecosystem="PyPI",
        source="requirements.txt",
    )


def make_vulnerability(
    identifier: str,
) -> VulnerabilityInfo:
    return VulnerabilityInfo(
        identifier=identifier,
        aliases=[identifier],
        dependency_name="requests",
        dependency_version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        summary="Test vulnerability",
        severity=Severity.CRITICAL,
        sources=[Provider.NVD],
        cvss=9.8,
    )


def make_provider(
    results: list[VulnerabilityInfo],
) -> Mock:
    provider = Mock(
        spec=BaseProvider,
    )

    provider.name = Provider.NVD
    provider.scan.return_value = results

    return provider


def test_execute_returns_provider_findings() -> None:
    dependency = make_dependency_2()

    findings = [
        make_vulnerability(
            "CVE-2026-0001",
        ),
    ]

    provider = make_provider(
        findings,
    )

    executor = ProviderExecutor(
        cache=ProviderCache(),
    )

    result = executor.execute(
        dependency=dependency,
        providers=[provider],
    )

    assert result == findings

    provider.scan.assert_called_once_with(
        dependency,
    )


def test_execute_returns_empty_list_when_no_providers() -> None:
    dependency = make_dependency_2()

    executor = ProviderExecutor(
        cache=ProviderCache(),
    )

    result = executor.execute(
        dependency=dependency,
        providers=[],
    )

    assert result == []


def test_execute_uses_cache_on_second_call() -> None:
    dependency = make_dependency_2()

    findings = [
        make_vulnerability(
            "CVE-2026-0001",
        ),
    ]

    provider = make_provider(
        findings,
    )

    executor = ProviderExecutor(
        cache=ProviderCache(),
    )

    first_result = executor.execute(
        dependency=dependency,
        providers=[provider],
    )

    second_result = executor.execute(
        dependency=dependency,
        providers=[provider],
    )

    assert first_result == findings
    assert second_result == findings

    provider.scan.assert_called_once_with(
        dependency,
    )


def test_execute_runs_multiple_providers() -> None:
    dependency = make_dependency_2()

    nvd_findings = [
        make_vulnerability(
            "CVE-2026-0001",
        ),
    ]

    second_findings = [
        make_vulnerability(
            "CVE-2026-0002",
        ),
    ]

    nvd_provider = make_provider(
        nvd_findings,
    )

    second_provider = make_provider(
        second_findings,
    )

    second_provider.name = Provider.OSV

    executor = ProviderExecutor(
        cache=ProviderCache(),
    )

    result = executor.execute(
        dependency=dependency,
        providers=[
            nvd_provider,
            second_provider,
        ],
    )

    assert len(result) == 2

    assert nvd_findings[0] in result
    assert second_findings[0] in result

    nvd_provider.scan.assert_called_once_with(
        dependency,
    )

    second_provider.scan.assert_called_once_with(
        dependency,
    )


def test_execute_continues_when_provider_fails() -> None:
    dependency = make_dependency_2()

    nvd_provider = Mock(
        spec=BaseProvider,
    )

    nvd_provider.name = Provider.NVD

    nvd_provider.scan.side_effect = RuntimeError(
        "NVD unavailable",
    )

    working_provider = make_provider(
        [
            make_vulnerability(
                "CVE-2026-0002",
            ),
        ],
    )

    working_provider.name = Provider.OSV

    executor = ProviderExecutor(
        cache=ProviderCache(),
    )

    result = executor.execute(
        dependency=dependency,
        providers=[
            nvd_provider,
            working_provider,
        ],
    )

    assert len(result) == 1

    assert result[0].identifier == ("CVE-2026-0002")

    nvd_provider.scan.assert_called_once_with(
        dependency,
    )

    working_provider.scan.assert_called_once_with(
        dependency,
    )
