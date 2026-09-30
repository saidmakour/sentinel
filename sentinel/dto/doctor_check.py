from dataclasses import dataclass

from sentinel.enums.doctor_status import DoctorStatus


@dataclass(slots=True, frozen=True)
class DoctorCheck:
    name: str
    status: DoctorStatus
    message: str
