from sentinel.config.settings import settings
from sentinel.doctor.checks.version import VersionCheck
from sentinel.dto.doctor_check import DoctorCheck
from sentinel.enums.doctor_status import DoctorStatus


def test_version_check_can_be_created() -> None:
    check = VersionCheck()

    assert check is not None


def test_run_returns_doctor_check() -> None:
    check = VersionCheck()

    results = check.run()
    result = results[0]

    assert isinstance(
        result,
        DoctorCheck,
    )


def test_run_returns_pass_status() -> None:
    check = VersionCheck()

    results = check.run()
    result = results[0]

    assert result.status == DoctorStatus.PASS


def test_run_returns_version_name() -> None:
    check = VersionCheck()

    results = check.run()
    result = results[0]

    assert result.name == "Sentinel version"


def test_run_returns_application_version() -> None:
    check = VersionCheck()

    results = check.run()
    result = results[0]

    assert result.message == settings.app_version
