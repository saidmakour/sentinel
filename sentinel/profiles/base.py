from abc import ABC
from abc import abstractmethod

from sentinel.enums.enricher import Enricher
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity


class BaseProfile(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def providers(self) -> list[Provider]: ...

    @property
    @abstractmethod
    def enrichers(self) -> list[Enricher]: ...

    @property
    @abstractmethod
    def minimum_severity(self) -> Severity: ...
