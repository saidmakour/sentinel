from enum import StrEnum


class Provider(StrEnum):
    OSV = "OSV"
    NVD = "NVD"
    GHSA = "GHSA"
    GITHUB_ADVISORY = "GITHUB_ADVISORY"
