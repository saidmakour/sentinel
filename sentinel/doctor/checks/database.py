from sqlalchemy import text

from sentinel.database.session import SessionLocal
from sentinel.doctor.checks.base import BaseDoctorCheck
from sentinel.dto.doctor_check import DoctorCheck
from sentinel.enums.doctor_status import DoctorStatus


class DatabaseCheck(BaseDoctorCheck):
    def run(
        self,
    ) -> list[DoctorCheck]:

        session = SessionLocal()

        try:
            session.execute(
                text("SELECT 1"),
            )

            return [
                DoctorCheck(
                    name="Database",
                    status=DoctorStatus.PASS,
                    message="Database connection successful",
                )
            ]
        except Exception as exc:
            return [
                DoctorCheck(
                    name="Database",
                    status=DoctorStatus.FAIL,
                    message=str(exc),
                )
            ]

        finally:
            session.close()
