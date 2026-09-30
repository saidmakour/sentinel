from abc import ABC
from abc import abstractmethod

from sentinel.scanners.registry import ScannerRegistry
from sentinel.services.version_comparators.registry import (
    VersionComparatorRegistry,
)


class ScannerPlugin(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def register_scanners(
        self,
        registry: ScannerRegistry,
    ) -> None: ...

    @abstractmethod
    def register_version_comparators(
        self,
        registry: VersionComparatorRegistry,
    ) -> None: ...
