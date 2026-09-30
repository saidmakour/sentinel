from dataclasses import dataclass

from sentinel.dto.doctor_check import DoctorCheck
from sentinel.enums.doctor_status import DoctorStatus


@dataclass(slots=True, frozen=True)
class DoctorReport:
    checks: list[DoctorCheck]

    @property
    def passed(self) -> int:
        return sum(check.status == DoctorStatus.PASS for check in self.checks)

    @property
    def warnings(self) -> int:
        return sum(
            check.status == DoctorStatus.WARNING for check in self.checks
        )

    @property
    def failed(self) -> int:
        return sum(check.status == DoctorStatus.FAIL for check in self.checks)

    @property
    def total(self) -> int:
        return len(self.checks)
