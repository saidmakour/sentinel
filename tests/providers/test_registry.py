from unittest.mock import MagicMock

from sentinel.doctor.checks.provider import ProviderCheck
from sentinel.dto.doctor_check import DoctorCheck
from sentinel.enums.doctor_status import DoctorStatus
from sentinel.enums.provider import Provider
from sentinel.providers.ghsa.provider import GHSAProvider
from sentinel.providers.github.provider import GitHubAdvisoryProvider
from sentinel.providers.registry import ProviderRegistry


def create_registry(
    *,
    available: bool = True,
) -> MagicMock:
    registry = MagicMock()

    registry.is_available.return_value = available

    return registry


def test_provider_check_can_be_created() -> None:
    registry = create_registry()

    check = ProviderCheck(
        Provider.OSV,
        registry=registry,
    )

    assert check is not None


def test_provider_check_returns_pass_when_provider_is_available() -> None:
    registry = create_registry(
        available=True,
    )

    check = ProviderCheck(
        Provider.OSV,
        registry=registry,
    )

    results = check.run()
    result = results[0]

    assert isinstance(
        result,
        DoctorCheck,
    )

    assert result.name == "provider.OSV"
    assert result.status == DoctorStatus.PASS
    assert result.message == "Provider OSV is available"

    registry.is_available.assert_called_once_with(
        Provider.OSV,
    )


def test_provider_check_returns_fail_when_provider_is_unavailable() -> None:
    registry = create_registry(
        available=False,
    )

    check = ProviderCheck(
        Provider.OSV,
        registry=registry,
    )

    results = check.run()
    result = results[0]

    assert result.name == "provider.OSV"
    assert result.status == DoctorStatus.FAIL
    assert result.message == "Provider unavailable"

    registry.is_available.assert_called_once_with(
        Provider.OSV,
    )


def test_provider_check_supports_nvd() -> None:
    registry = create_registry()

    check = ProviderCheck(
        Provider.NVD,
        registry=registry,
    )

    results = check.run()
    result = results[0]

    assert result.name == "provider.NVD"
    assert result.status == DoctorStatus.PASS


def test_provider_check_supports_ghsa() -> None:
    registry = create_registry()

    check = ProviderCheck(
        Provider.GHSA,
        registry=registry,
    )

    results = check.run()
    result = results[0]

    assert result.name == "provider.GHSA"
    assert result.status == DoctorStatus.PASS


def test_provider_check_supports_github_advisory() -> None:
    registry = create_registry()

    check = ProviderCheck(
        Provider.GITHUB_ADVISORY,
        registry=registry,
    )

    results = check.run()
    result = results[0]

    assert result.name == "provider.GITHUB_ADVISORY"
    assert result.status == DoctorStatus.PASS


def test_create_returns_ghsa_provider(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "sentinel.providers.registry.settings.ghsa_enabled",
        True,
    )

    registry = ProviderRegistry()

    providers = registry.create(
        [
            Provider.GHSA,
        ],
    )
    assert len(providers) == 1
    assert isinstance(
        providers[0],
        GHSAProvider,
    )


def test_create_all_contains_ghsa_provider(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "sentinel.providers.registry.settings.osv_enabled",
        False,
    )

    monkeypatch.setattr(
        "sentinel.providers.registry.settings.nvd_enabled",
        False,
    )

    monkeypatch.setattr(
        "sentinel.providers.registry.settings.ghsa_enabled",
        True,
    )

    registry = ProviderRegistry()

    providers = registry.create_all()

    assert any(isinstance(provider, GHSAProvider) for provider in providers)
    assert isinstance(
        providers[0],
        GHSAProvider,
    )


def test_create_returns_github_provider(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "sentinel.providers.registry.settings.github_advisory_enabled",
        True,
    )

    registry = ProviderRegistry()

    providers = registry.create(
        [
            Provider.GITHUB_ADVISORY,
        ],
    )
    assert len(providers) == 1
    assert isinstance(
        providers[0],
        GitHubAdvisoryProvider,
    )
