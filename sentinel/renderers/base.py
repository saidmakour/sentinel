from abc import ABC
from abc import abstractmethod

from sentinel.dto.scan_result import ScanResult


class BaseRenderer(ABC):
    @abstractmethod
    def render(
        self,
        result: ScanResult,
    ) -> str:
        """
        Render a scan result into a string representation.
        """
