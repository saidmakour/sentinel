from sentinel.doctor.checks.base import BaseDoctorCheck
from sentinel.dto.doctor_check import DoctorCheck
from sentinel.enums.doctor_status import DoctorStatus


class DummyDoctorCheck(BaseDoctorCheck):
    def run(
        self,
    ) -> DoctorCheck:
        return DoctorCheck(
            name="Dummy",
            status=DoctorStatus.PASS,
            message="OK",
        )


def test_base_doctor_check_can_be_implemented() -> None:
    check = DummyDoctorCheck()

    assert check is not None


def test_dummy_doctor_check_returns_doctor_check() -> None:
    check = DummyDoctorCheck()

    result = check.run()

    assert isinstance(
        result,
        DoctorCheck,
    )


def test_dummy_doctor_check_returns_expected_values() -> None:
    check = DummyDoctorCheck()

    result = check.run()

    assert result.name == "Dummy"
    assert result.status == DoctorStatus.PASS
    assert result.message == "OK"
