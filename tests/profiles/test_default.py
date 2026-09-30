from sentinel.enums.enricher import Enricher
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity
from sentinel.profiles.default import DefaultProfile


def test_default_profile_can_be_created() -> None:
    profile = DefaultProfile()

    assert profile is not None


def test_default_profile_name() -> None:
    profile = DefaultProfile()

    assert profile.name == "default"


def test_default_profile_providers() -> None:
    profile = DefaultProfile()

    assert profile.providers == [
        Provider.OSV,
        Provider.NVD,
    ]


def test_default_profile_enrichers() -> None:
    profile = DefaultProfile()

    assert profile.enrichers == [
        Enricher.KEV,
        Enricher.EPSS,
    ]


def test_default_profile_minimum_severity() -> None:
    profile = DefaultProfile()

    assert profile.minimum_severity == Severity.LOW
