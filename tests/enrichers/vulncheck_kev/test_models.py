from datetime import datetime

from sentinel.enrichers.vulncheck_kev.models import VulnCheckKEVVulnerability


def test_vulncheck_kev_vulnerability_creation() -> None:
    vulnerability = VulnCheckKEVVulnerability(
        cve_ids=[
            "CVE-2025-0001",
        ],
        vendor="Example Vendor",
        product="Example Product",
        short_description="Example vulnerability",
        vulnerability_name="Example Vulnerability",
        required_action="Apply the vendor patch.",
        known_ransomware="Known",
        reported_exploited_by_canaries=True,
    )

    assert vulnerability.cve_ids == [
        "CVE-2025-0001",
    ]
    assert vulnerability.vendor == "Example Vendor"
    assert vulnerability.product == "Example Product"
    assert vulnerability.short_description == "Example vulnerability"
    assert vulnerability.vulnerability_name == "Example Vulnerability"
    assert vulnerability.required_action == "Apply the vendor patch."
    assert vulnerability.known_ransomware == "Known"
    assert vulnerability.reported_exploited_by_canaries is True
    assert vulnerability.date_added is None
    assert vulnerability.cisa_date_added is None
    assert vulnerability.due_date is None


def test_vulncheck_kev_vulnerability_with_dates() -> None:
    date_added = datetime(
        2025,
        1,
        10,
        12,
        30,
    )
    cisa_date_added = datetime(
        2025,
        1,
        11,
        8,
        15,
    )
    due_date = datetime(
        2025,
        2,
        10,
        0,
        0,
    )

    vulnerability = VulnCheckKEVVulnerability(
        cve_ids=[
            "CVE-2025-0001",
            "CVE-2025-0002",
        ],
        vendor="Example Vendor",
        product="Example Product",
        short_description="Example vulnerability",
        vulnerability_name="Example Vulnerability",
        required_action="Apply the vendor patch.",
        known_ransomware="Known",
        reported_exploited_by_canaries=False,
        date_added=date_added,
        cisa_date_added=cisa_date_added,
        due_date=due_date,
    )

    assert vulnerability.cve_ids == [
        "CVE-2025-0001",
        "CVE-2025-0002",
    ]
    assert vulnerability.date_added == date_added
    assert vulnerability.cisa_date_added == cisa_date_added
    assert vulnerability.due_date == due_date
    assert vulnerability.reported_exploited_by_canaries is False


def test_vulncheck_kev_vulnerability_supports_multiple_cves() -> None:
    vulnerability = VulnCheckKEVVulnerability(
        cve_ids=[
            "CVE-2025-0001",
            "CVE-2025-0002",
            "CVE-2025-0003",
        ],
        vendor="Example Vendor",
        product="Example Product",
        short_description="Multiple CVEs",
        vulnerability_name="Example Vulnerability",
        required_action="Apply the vendor patch.",
        known_ransomware="Unknown",
        reported_exploited_by_canaries=False,
    )

    assert len(vulnerability.cve_ids) == 3
    assert "CVE-2025-0001" in vulnerability.cve_ids
    assert "CVE-2025-0002" in vulnerability.cve_ids
    assert "CVE-2025-0003" in vulnerability.cve_ids
