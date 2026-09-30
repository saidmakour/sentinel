from unittest.mock import MagicMock

from sentinel.doctor.checks.base import BaseDoctorCheck
from sentinel.doctor.checks.provider import ProviderCheck
from sentinel.doctor.service import DoctorService
from sentinel.dto.doctor_report import DoctorReport
from sentinel.enums.provider import Provider
from sentinel.providers.registry import ProviderRegistry


def test_doctor_service_can_be_created() -> None:
    service = DoctorService()

    assert service is not None
    assert service.checks


def test_doctor_service_uses_provided_provider_registry() -> None:
    registry = MagicMock(
        spec=ProviderRegistry,
    )

    service = DoctorService(
        provider_registry=registry,
    )

    assert service.provider_registry is registry


def test_doctor_service_contains_provider_checks() -> None:
    registry = MagicMock(
        spec=ProviderRegistry,
    )

    service = DoctorService(
        provider_registry=registry,
    )

    provider_checks = [
        check for check in service.checks if isinstance(check, ProviderCheck)
    ]

    assert len(provider_checks) == 3

    providers = {check.provider for check in provider_checks}

    assert providers == {
        Provider.OSV,
        Provider.NVD,
        Provider.GHSA,
    }


def test_doctor_service_injects_same_registry_into_provider_checks() -> None:
    registry = MagicMock(
        spec=ProviderRegistry,
    )

    service = DoctorService(
        provider_registry=registry,
    )

    provider_checks = [
        check for check in service.checks if isinstance(check, ProviderCheck)
    ]

    assert len(provider_checks) == 3

    for check in provider_checks:
        assert check.registry is registry


def test_doctor_service_run_returns_doctor_report() -> None:
    check_one = MagicMock(
        spec=BaseDoctorCheck,
    )
    check_two = MagicMock(
        spec=BaseDoctorCheck,
    )

    result_one = MagicMock()
    result_two = MagicMock()

    check_one.run.return_value = [
        result_one,
    ]
    check_two.run.return_value = [
        result_two,
    ]

    service = DoctorService(
        checks=[
            check_one,
            check_two,
        ],
    )

    result = service.run()

    assert isinstance(
        result,
        DoctorReport,
    )

    assert result.checks == [
        result_one,
        result_two,
    ]

    check_one.run.assert_called_once_with()
    check_two.run.assert_called_once_with()


def test_doctor_service_run_executes_all_checks() -> None:
    checks = [
        MagicMock(
            spec=BaseDoctorCheck,
        )
        for _ in range(3)
    ]

    service = DoctorService(
        checks=checks,
    )

    service.run()

    for check in checks:
        check.run.assert_called_once_with()


def test_doctor_service_accepts_custom_checks() -> None:
    checks = [
        MagicMock(
            spec=BaseDoctorCheck,
        ),
    ]

    service = DoctorService(
        checks=checks,
    )

    assert service.checks is checks


def test_doctor_service_default_configuration_contains_expected_checks() -> (
    None
):
    service = DoctorService()

    assert len(service.checks) == 7
    assert isinstance(
        service.checks[0],
        BaseDoctorCheck,
    )
    assert isinstance(
        service.checks[1],
        BaseDoctorCheck,
    )
    assert isinstance(
        service.checks[2],
        BaseDoctorCheck,
    )
    assert isinstance(
        service.checks[3],
        BaseDoctorCheck,
    )
    assert isinstance(
        service.checks[4],
        ProviderCheck,
    )
    assert isinstance(
        service.checks[5],
        ProviderCheck,
    )
    assert isinstance(
        service.checks[6],
        ProviderCheck,
    )
