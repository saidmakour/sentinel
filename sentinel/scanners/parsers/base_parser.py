from __future__ import annotations

from abc import ABC
from abc import abstractmethod
from pathlib import Path

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.ecosystem import Ecosystem


class BaseParser(ABC):
    """
    Base class for dependency parsers.
    """

    FILE: str
    PRIORITY: int

    @abstractmethod
    def supports(self, project_path: Path) -> bool:
        """
        Return True if this parser can parse the project.
        """
        raise NotImplementedError

    @abstractmethod
    def parse(
        self,
        project_path: Path,
    ) -> list[ScannedDependency]:
        """
        Extract dependencies from the project.
        """
        raise NotImplementedError

    def make_dependency(
        self,
        *,
        name: str,
        version: str,
        ecosystem: Ecosystem,
    ) -> ScannedDependency:
        return ScannedDependency(
            name=name,
            version=version,
            ecosystem=ecosystem,
            source=self.FILE,
            priority=self.PRIORITY,
        )
