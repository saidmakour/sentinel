from pathlib import Path

from sentinel.doctor.checks.base import BaseDoctorCheck
from sentinel.dto.doctor_check import DoctorCheck
from sentinel.enums.doctor_status import DoctorStatus


class DirectoryCheck(BaseDoctorCheck):
    def __init__(
        self,
        directories: dict[str, Path],
    ) -> None:
        self.directories = directories

    def run(self) -> list[DoctorCheck]:
        results: list[DoctorCheck] = []

        for name, path in self.directories.items():
            if path.is_dir():
                results.append(
                    DoctorCheck(
                        name=name,
                        status=DoctorStatus.PASS,
                        message=str(path),
                    ),
                )
                continue

            results.append(
                DoctorCheck(
                    name=name,
                    status=DoctorStatus.FAIL,
                    message=f"Directory not found: {path}",
                ),
            )

        return results
