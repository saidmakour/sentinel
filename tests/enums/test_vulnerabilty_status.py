from enum import StrEnum

from sentinel.enums.vulnerability_status import VulnerabilityStatus
from sentinel.models.vulnerability import Vulnerability


def test_vulnerability_status_is_str_enum():
    assert issubclass(VulnerabilityStatus, StrEnum)


def test_vulnerability_status_values():

    vulnerability = Vulnerability(
        repository_id=1,
        identifier="CVE-2026-0001",
        status=VulnerabilityStatus.OPEN,
    )

    assert vulnerability.status == VulnerabilityStatus.OPEN
