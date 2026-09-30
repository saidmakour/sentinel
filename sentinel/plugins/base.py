from abc import ABC
from abc import abstractmethod

from sentinel.enums.ecosystem import Ecosystem
from sentinel.scanners.definition import ScannerDefinition
from sentinel.services.version_comparators.base import BaseVersionComparator


class SentinelPlugin(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def languages(self) -> tuple[str, ...]: ...

    @property
    @abstractmethod
    def scanners(
        self,
    ) -> dict[str, ScannerDefinition]: ...

    @property
    @abstractmethod
    def comparators(
        self,
    ) -> dict[Ecosystem, BaseVersionComparator]: ...
