from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(slots=True)
class VulnCheckKEVVulnerability:
    """
    VulnCheck Known Exploited Vulnerability.
    """

    cve_ids: list[str]

    vendor: str
    product: str

    short_description: str
    vulnerability_name: str

    required_action: str
    known_ransomware: str

    reported_exploited_by_canaries: bool

    date_added: datetime | None = None
    cisa_date_added: datetime | None = None
    due_date: datetime | None = None
