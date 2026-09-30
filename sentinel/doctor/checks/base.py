from abc import ABC
from abc import abstractmethod

from sentinel.dto.doctor_check import DoctorCheck


class BaseDoctorCheck(ABC):
    @abstractmethod
    def run(
        self,
    ) -> list[DoctorCheck]:
        """Execute the check."""
