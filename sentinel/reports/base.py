from abc import ABC
from abc import abstractmethod

from sentinel.dto.scan_report import ScanReport


class BaseReportRenderer(ABC):
    @abstractmethod
    def render(
        self,
        report: ScanReport,
    ) -> str:
        """
        Render a scan report into a string representation.
        """
