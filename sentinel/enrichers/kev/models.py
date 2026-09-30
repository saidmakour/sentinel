from dataclasses import dataclass
from datetime import date


@dataclass(slots=True, frozen=True)
class KEVVulnerability:
    cve_id: str
    date_added: date | None
    due_date: date | None
    vendor: str
    product: str
    required_action: str
    known_ransomware: str


@dataclass(slots=True, frozen=True)
class KEVResponse:
    vulnerabilities: list[KEVVulnerability]
