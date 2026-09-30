from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity
from sentinel.profiles.fast import FastProfile


def test_fast_profile() -> None:

    profile = FastProfile()

    assert profile.name == "fast"

    assert profile.providers == [
        Provider.OSV,
    ]

    assert profile.enrichers == []

    assert profile.minimum_severity == Severity.HIGH
