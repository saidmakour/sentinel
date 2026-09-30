from sentinel.config.settings import settings
from sentinel.doctor.checks.base import BaseDoctorCheck
from sentinel.dto.doctor_check import DoctorCheck
from sentinel.enums.doctor_status import DoctorStatus


class VersionCheck(BaseDoctorCheck):
    def run(
        self,
    ) -> list[DoctorCheck]:

        return [
            DoctorCheck(
                name="Sentinel version",
                status=DoctorStatus.PASS,
                message=settings.app_version,
            )
        ]
