from sentinel.enums.enricher import Enricher
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity
from sentinel.profiles.base import BaseProfile


class FastProfile(BaseProfile):
    @property
    def name(self) -> str:
        return "fast"

    @property
    def providers(self) -> list[Provider]:
        return [
            Provider.OSV,
        ]

    @property
    def enrichers(self) -> list[Enricher]:
        return []

    @property
    def minimum_severity(self) -> Severity:
        return Severity.HIGH
