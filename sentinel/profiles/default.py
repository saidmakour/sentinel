from sentinel.enums.enricher import Enricher
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity
from sentinel.profiles.base import BaseProfile


class DefaultProfile(BaseProfile):
    @property
    def name(self) -> str:
        return "default"

    @property
    def providers(self) -> list[Provider]:
        return [
            Provider.OSV,
            Provider.NVD,
            Provider.GHSA,
            Provider.GITHUB_ADVISORY,
        ]

    @property
    def enrichers(self) -> list[Enricher]:
        return [
            Enricher.KEV,
            Enricher.EPSS,
        ]

    @property
    def minimum_severity(self) -> Severity:
        return Severity.LOW
