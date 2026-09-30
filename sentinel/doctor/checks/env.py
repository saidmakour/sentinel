from pathlib import Path

from sentinel.doctor.checks.base import BaseDoctorCheck
from sentinel.dto.doctor_check import DoctorCheck
from sentinel.enums.doctor_status import DoctorStatus


class EnvCheck(BaseDoctorCheck):
    def __init__(
        self,
        env_path: Path | None = None,
    ) -> None:
        self.env_path = env_path or Path(".env")

    def run(
        self,
    ) -> list[DoctorCheck]:

        if not self.env_path.exists():
            return [
                DoctorCheck(
                    name=".env",
                    status=DoctorStatus.FAIL,
                    message=f"File not found: {self.env_path}",
                )
            ]

        if not self.env_path.is_file():
            return [
                DoctorCheck(
                    name=".env",
                    status=DoctorStatus.FAIL,
                    message=f"Not a file: {self.env_path}",
                )
            ]

        try:
            self.env_path.read_text(
                encoding="utf-8",
            )
        except OSError as exc:
            return [
                DoctorCheck(
                    name=".env",
                    status=DoctorStatus.FAIL,
                    message=str(exc),
                )
            ]

        return [
            DoctorCheck(
                name=".env",
                status=DoctorStatus.PASS,
                message=f"{self.env_path} available",
            )
        ]
