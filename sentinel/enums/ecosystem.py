from enum import StrEnum


class Ecosystem(StrEnum):
    PYPI = "PyPI"
    NPM = "npm"
    COMPOSER = "Packagist"
    MAVEN = "Maven"
    GOLANG = "Go"
    RUBYGEMS = "RubyGems"
