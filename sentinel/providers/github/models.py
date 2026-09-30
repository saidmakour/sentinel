from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field


@dataclass(slots=True)
class GitHubIdentifier:
    type: str
    value: str


@dataclass(slots=True)
class GitHubPackage:
    ecosystem: str
    name: str


@dataclass(slots=True)
class GitHubVulnerability:
    package: GitHubPackage
    vulnerable_version_range: str
    first_patched_version: str | None = None
    vulnerable_functions: list[str] = field(
        default_factory=list[str],
    )


@dataclass(slots=True)
class GitHubCVSS:
    score: float | None = None
    vector_string: str | None = None


@dataclass(slots=True)
class GitHubCVSSSeverities:
    cvss_v3: GitHubCVSS | None = None
    cvss_v4: GitHubCVSS | None = None


@dataclass(slots=True)
class GitHubAdvisory:
    ghsa_id: str
    summary: str
    description: str | None
    severity: str
    cve_id: str | None

    identifiers: list[GitHubIdentifier]
    vulnerabilities: list[GitHubVulnerability]

    cvss: GitHubCVSS | None = None
    cvss_severities: GitHubCVSSSeverities | None = None

    published_at: str | None = None
    updated_at: str | None = None
    withdrawn_at: str | None = None

    references: list[str] = field(
        default_factory=list[str],
    )
