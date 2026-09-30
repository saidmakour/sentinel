from datetime import datetime
from unittest.mock import MagicMock
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from sentinel.api.app import app
from sentinel.dto.remediation_info import RemediationInfo
from sentinel.dto.remediation_info import RemediationRule
from sentinel.dto.scan_report import ScanReport
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.enums.scan_status import ScanStatus
from sentinel.enums.security_status import SecurityStatus
from sentinel.enums.severity import Severity
from sentinel.enums.source_type import SourceType
from sentinel.enums.vulnerability_status import VulnerabilityStatus
from sentinel.exceptions.scan import ScanNotFoundError
from sentinel.models.user import User
from sentinel.security.jwt import create_access_token
from sentinel.security.password import hash_password

client = TestClient(app)


def create_user(
    db_session: Session,
    username: str,
    is_admin: bool = False,
) -> User:
    user = User(
        username=username,
        password_hash=hash_password("password"),
        is_active=True,
        is_admin=is_admin,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def auth_headers(user: User) -> dict[str, str]:
    token = create_access_token(
        user_id=user.id,
        username=user.username,
    )
    return {
        "Authorization": f"Bearer {token}",
    }


def create_report() -> ScanReport:
    finding = VulnerabilityInfo(
        dependency_name="requests",
        dependency_version="2.31.0",
        ecosystem=Ecosystem.PYPI,
        identifier="CVE-2024-12345",
        aliases=["CVE-2024-12345"],
        severity=Severity.HIGH,
        sources=[
            Provider.NVD,
        ],
        cvss=8.1,
        summary="A vulnerability in requests package.",
        status=VulnerabilityStatus.OPEN,
        remediation=RemediationInfo(
            rules=[
                RemediationRule(
                    introduced="2.0.0",
                    fixed="2.32.0",
                    affected_range="<2.32.0",
                ),
            ],
        ),
        fixed_versions=["2.32.0"],
        known_exploited=True,
        epss_score=0.42,
        epss_percentile=0.75,
        kev_vendor="Test Vendor",
        kev_product="requests",
        kev_required_action="Update to a fixed version.",
        kev_known_ransomware="Known",
    )

    return ScanReport(
        scan_id=1,
        repository_id=1,
        profile_name="default",
        engine_version="1.0-dev",
        status=ScanStatus.SUCCESS,
        security_status=SecurityStatus.AT_RISK,
        started_at=datetime(2026, 8, 11, 14, 0, 0),
        finished_at=datetime(2026, 8, 11, 14, 2, 0),
        duration_seconds=120,
        source_type=SourceType.GIT,
        source_reference="https://github.com/test/project.git",
        source_branch="main",
        source_commit="abc123",
        findings=[
            finding,
        ],
        dependency_summaries=[],
        critical_count=0,
        high_count=1,
        medium_count=0,
        low_count=0,
        risk_score=5,
        error_message=None,
    )


@patch("sentinel.api.routers.scans.ScanReportService")
def test_get_scan_report(
    service_mock: MagicMock,
    client: TestClient,
    db_session: Session,
) -> None:
    service_mock.return_value.get_report.return_value = create_report()
    user = create_user(
        db_session,
        "user",
    )
    response = client.get(
        "/scans/1/report",
        headers=auth_headers(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["scan_id"] == 1
    assert data["repository_id"] == 1
    assert data["profile_name"] == "default"
    assert data["engine_version"] == "1.0-dev"
    assert data["status"] == ScanStatus.SUCCESS.value

    assert data["duration_seconds"] == 120

    assert data["source_type"] == SourceType.GIT.value
    assert data["source_reference"] == ("https://github.com/test/project.git")
    assert data["source_branch"] == "main"
    assert data["source_commit"] == "abc123"

    assert data["critical_count"] == 0
    assert data["high_count"] == 1
    assert data["medium_count"] == 0
    assert data["low_count"] == 0
    assert data["risk_score"] == 5
    assert data["error_message"] is None
    assert data["security_status"] == SecurityStatus.AT_RISK.value

    assert len(data["findings"]) == 1

    finding = data["findings"][0]

    assert finding["dependency_name"] == "requests"
    assert finding["dependency_version"] == "2.31.0"
    assert finding["ecosystem"] == Ecosystem.PYPI.value

    assert finding["identifier"] == "CVE-2024-12345"
    assert finding["aliases"] == ["CVE-2024-12345"]
    assert finding["sources"] == [Provider.NVD.value]

    assert finding["severity"] == Severity.HIGH.value
    assert finding["cvss"] == 8.1
    assert finding["status"] == VulnerabilityStatus.OPEN.value

    assert finding["summary"] == ("A vulnerability in requests package.")

    assert finding["fixed_versions"] == ["2.32.0"]

    assert finding["remediation"]["rules"][0] == {
        "introduced": "2.0.0",
        "fixed": "2.32.0",
        "affected_range": "<2.32.0",
    }

    assert finding["known_exploited"] is True
    assert finding["epss_score"] == 0.42
    assert finding["epss_percentile"] == 0.75

    assert finding["kev_vendor"] == "Test Vendor"
    assert finding["kev_product"] == "requests"
    assert finding["kev_required_action"] == ("Update to a fixed version.")
    assert finding["kev_known_ransomware"] == "Known"


@patch("sentinel.api.routers.scans.ScanReportService")
def test_export_scan_report_json(
    service_mock: MagicMock,
    client: TestClient,
    db_session: Session,
) -> None:
    service_mock.return_value.get_report.return_value = create_report()
    user = create_user(
        db_session,
        "user",
    )

    response = client.get(
        "/scans/1/report/export?format=json",
        headers=auth_headers(user),
    )

    assert response.status_code == 200

    assert response.json()["risk"]["score"] == 5

    assert response.json()["findings"][0]["identifier"] == "CVE-2024-12345"


@patch("sentinel.api.routers.scans.ScanReportService")
def test_export_scan_report_html(
    service_mock: MagicMock,
    client: TestClient,
    db_session: Session,
) -> None:
    service_mock.return_value.get_report.return_value = create_report()
    user = create_user(
        db_session,
        "user",
    )
    response = client.get(
        "/scans/1/report/export?format=html", headers=auth_headers(user)
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(
        "text/html",
    )
    assert "Sentinel Vulnerability Report" in response.text


@patch("sentinel.api.routers.scans.ScanReportService")
def test_export_scan_report_markdown(
    service_mock: MagicMock,
    client: TestClient,
    db_session: Session,
) -> None:
    service_mock.return_value.get_report.return_value = create_report()
    user = create_user(
        db_session,
        "user",
    )
    response = client.get(
        "/scans/1/report/export?format=markdown", headers=auth_headers(user)
    )

    assert response.status_code == 200
    assert "Sentinel Vulnerability Report" in response.text


@patch("sentinel.api.routers.scans.ScanReportService")
def test_export_scan_report_sarif(
    service_mock: MagicMock,
    client: TestClient,
    db_session: Session,
) -> None:
    service_mock.return_value.get_report.return_value = create_report()
    user = create_user(
        db_session,
        "user",
    )
    response = client.get(
        "/scans/1/report/export?format=sarif",
        headers=auth_headers(user),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["version"] == "2.1.0"
    assert data["runs"][0]["tool"]["driver"]["name"] == "Sentinel"


@patch("sentinel.api.routers.scans.ScanReportService")
def test_export_scan_report_with_unknown_format(
    service_mock: MagicMock,
    client: TestClient,
    db_session: Session,
) -> None:
    service_mock.return_value.get_report.return_value = create_report()

    user = create_user(
        db_session,
        "user",
    )

    response = client.get(
        "/scans/1/report/export?format=unknown",
        headers=auth_headers(user),
    )

    assert response.status_code == 400
    assert "Unknown renderer" in response.json()["detail"]


@patch("sentinel.api.routers.scans.ScanReportService")
def test_export_scan_report_not_found(
    service_mock: MagicMock,
    client: TestClient,
    db_session: Session,
) -> None:
    service_mock.return_value.get_report.side_effect = ScanNotFoundError(
        "Scan '999' not found",
    )

    user = create_user(
        db_session,
        "user",
    )

    response = client.get(
        "/scans/999/report/export?format=json",
        headers=auth_headers(user),
    )

    assert response.status_code == 404

    assert response.json() == {
        "detail": "Scan '999' not found",
    }


def test_scan_report_is_exposed_in_openapi() -> None:
    openapi = app.openapi()

    operation = openapi["paths"]["/scans/{scan_id}/report"]["get"]

    assert operation["responses"]["200"]["content"]["application/json"][
        "schema"
    ]["$ref"] == ("#/components/schemas/ScanReportSchema")


@patch("sentinel.api.routers.scans.ScanReportService")
def test_export_scan_report_format_is_case_insensitive(
    service_mock: MagicMock,
    client: TestClient,
    db_session: Session,
) -> None:
    service_mock.return_value.get_report.return_value = create_report()
    user = create_user(
        db_session,
        "user",
    )
    response = client.get(
        "/scans/1/report/export?format=JSON", headers=auth_headers(user)
    )

    assert response.status_code == 200
    assert response.json()["risk"]["score"] == 5


@patch("sentinel.api.routers.scans.ScanReportService")
def test_export_scan_report_html_with_local_source(
    service_mock: MagicMock,
    client: TestClient,
    db_session: Session,
) -> None:
    report = create_report()
    user = create_user(
        db_session,
        "user",
    )
    report.source_type = SourceType.LOCAL
    report.source_reference = None
    report.source_branch = None
    report.source_commit = None

    service_mock.return_value.get_report.return_value = report

    response = client.get(
        "/scans/1/report/export?format=html",
        headers=auth_headers(user),
    )

    assert response.status_code == 200
    assert "Sentinel Vulnerability Report" in response.text
    assert "Branch" in response.text
    assert "Commit" in response.text


@patch("sentinel.api.routers.scans.ScanReportService")
def test_export_scan_report_json_content_type(
    service_mock: MagicMock,
    client: TestClient,
    db_session: Session,
) -> None:
    service_mock.return_value.get_report.return_value = create_report()
    user = create_user(
        db_session,
        "user",
    )
    response = client.get(
        "/scans/1/report/export?format=json",
        headers=auth_headers(user),
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(
        "application/json",
    )


@patch("sentinel.api.routers.scans.ScanReportService")
def test_export_scan_report_markdown_content_type(
    service_mock: MagicMock,
    client: TestClient,
    db_session: Session,
) -> None:
    service_mock.return_value.get_report.return_value = create_report()
    user = create_user(
        db_session,
        "user",
    )
    response = client.get(
        "/scans/1/report/export?format=markdown",
        headers=auth_headers(user),
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(
        "text/markdown",
    )


def test_scan_report_schema_contains_security_status() -> None:
    openapi = app.openapi()

    schema = openapi["components"]["schemas"]["ScanReportSchema"]

    assert "security_status" in schema["properties"]
