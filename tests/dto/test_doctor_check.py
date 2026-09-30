from sentinel.dto.doctor_check import DoctorCheck
from sentinel.enums.doctor_status import DoctorStatus


def test_doctor_check_can_be_created() -> None:
    check = DoctorCheck(
        name="Database",
        status=DoctorStatus.PASS,
        message="Connection successful",
    )

    assert check.name == "Database"
    assert check.status == DoctorStatus.PASS
    assert check.message == "Connection successful"
