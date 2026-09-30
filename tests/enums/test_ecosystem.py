from enum import StrEnum

from sentinel.enums.ecosystem import Ecosystem


def test_ecosystem_is_str_enum():
    assert issubclass(Ecosystem, StrEnum)


def test_ecosystem_values():
    assert Ecosystem.PYPI.value == "PyPI"
    assert Ecosystem.NPM.value == "npm"
    assert Ecosystem.COMPOSER.value == "Packagist"
    assert Ecosystem.MAVEN.value == "Maven"
    assert Ecosystem.GOLANG.value == "Go"


def test_ecosystem_string_behavior():
    assert str(Ecosystem.PYPI) == "PyPI"
    assert str(Ecosystem.NPM) == "npm"
