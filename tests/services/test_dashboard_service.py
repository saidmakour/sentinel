from unittest.mock import MagicMock

from sentinel.enums.scan_status import ScanStatus
from sentinel.services.dashboard_service import DashboardService


def test_dashboard_summary_empty() -> None:

    session = MagicMock()

    service = DashboardService(
        session,
    )
    service.scan_repo = MagicMock()
    service.finding_repo = MagicMock()

    service.scan_repo.get_all.return_value = []

    service.finding_repo.get_all.return_value = []

    service.finding_repo.count_by_severity.return_value = {}

    summary = service.summary()

    assert summary.total_scans == 0
    assert summary.completed_scans == 0
    assert summary.failed_scans == 0
    assert summary.total_findings == 0

    assert summary.findings_by_severity == {}


def test_repository_summary() -> None:

    session = MagicMock()

    service = DashboardService(
        session,
    )
    service.scan_repo = MagicMock()
    service.finding_repo = MagicMock()
    scan = MagicMock()
    scan.status = "FINISHED"
    scan.profile_name = "default"

    service.scan_repo.list_by_repository.return_value = [
        scan,
    ]

    service.finding_repo.count_by_repository.return_value = 5

    summary = service.repository_summary(
        1,
    )

    assert summary.repository_id == 1
    assert summary.total_scans == 1
    assert summary.total_findings == 5
    assert summary.last_scan_status == "FINISHED"
    assert summary.last_scan_profile == "default"


def test_risk_summary() -> None:

    session = MagicMock()

    service = DashboardService(
        session,
    )

    service.finding_repo = MagicMock()

    service.finding_repo.count_by_repository_and_severity.return_value = {
        "CRITICAL": 2,
        "HIGH": 5,
        "MEDIUM": 10,
        "LOW": 20,
    }

    summary = service.risk_summary(
        1,
        "backend",
    )

    assert summary.repository_id == 1
    assert summary.repository_name == "backend"

    assert summary.critical_count == 2
    assert summary.high_count == 5
    assert summary.medium_count == 10
    assert summary.low_count == 20

    assert summary.total_findings == 37

    assert summary.risk_score == (2 * 10 + 5 * 5 + 10 * 2 + 20)


def test_risk_overview() -> None:

    session = MagicMock()

    service = DashboardService(
        session,
    )

    service.repository_repo = MagicMock()
    service.finding_repo = MagicMock()

    repo1 = MagicMock()
    repo1.id = 1
    repo1.name = "backend"

    repo2 = MagicMock()
    repo2.id = 2
    repo2.name = "frontend"

    service.repository_repo.get_all.return_value = [
        repo1,
        repo2,
    ]

    service.finding_repo.count_by_repository_and_severity.side_effect = [
        {
            "CRITICAL": 2,
            "HIGH": 5,
        },
        {
            "HIGH": 1,
        },
    ]

    result = service.risk_overview()

    assert len(result) == 2

    assert result[0].repository_name == "backend"
    assert result[0].risk_score > result[1].risk_score


def test_dashboard_summary_counts_completed_and_failed_scans() -> None:
    session = MagicMock()

    service = DashboardService(
        session,
    )
    service.scan_repo = MagicMock()
    service.finding_repo = MagicMock()

    scan_success = MagicMock()
    scan_success.status = ScanStatus.SUCCESS

    scan_failed = MagicMock()
    scan_failed.status = ScanStatus.FAILED

    scan_started = MagicMock()
    scan_started.status = ScanStatus.STARTED

    service.scan_repo.get_all.return_value = [
        scan_success,
        scan_failed,
        scan_started,
    ]

    service.finding_repo.get_all.return_value = [
        MagicMock(),
        MagicMock(),
    ]

    service.finding_repo.count_by_severity.return_value = {
        "CRITICAL": 1,
        "HIGH": 1,
    }

    summary = service.summary()

    assert summary.total_scans == 3
    assert summary.completed_scans == 1
    assert summary.failed_scans == 1
    assert summary.total_findings == 2

    assert summary.findings_by_severity == {
        "CRITICAL": 1,
        "HIGH": 1,
    }


def test_repository_summary_without_scans() -> None:
    session = MagicMock()

    service = DashboardService(
        session,
    )
    service.scan_repo = MagicMock()
    service.finding_repo = MagicMock()

    service.scan_repo.list_by_repository.return_value = []

    service.finding_repo.count_by_repository.return_value = 0

    summary = service.repository_summary(
        1,
    )

    assert summary.repository_id == 1
    assert summary.total_scans == 0
    assert summary.total_findings == 0
    assert summary.last_scan_status is None
    assert summary.last_scan_profile is None


def test_risk_overview_without_repositories() -> None:
    session = MagicMock()

    service = DashboardService(
        session,
    )

    service.repository_repo = MagicMock()

    service.repository_repo.get_all.return_value = []

    result = service.risk_overview()

    assert result == []


def test_global_risk_summary() -> None:
    session = MagicMock()

    service = DashboardService(
        session,
    )

    service.finding_repo = MagicMock()

    scan1 = MagicMock()
    scan1.repository_id = 1

    scan2 = MagicMock()
    scan2.repository_id = 2

    finding1 = MagicMock()
    finding1.severity = "CRITICAL"
    finding1.scan = scan1

    finding2 = MagicMock()
    finding2.severity = "HIGH"
    finding2.scan = scan1

    finding3 = MagicMock()
    finding3.severity = "HIGH"
    finding3.scan = scan2

    finding4 = MagicMock()
    finding4.severity = "MEDIUM"
    finding4.scan = None

    finding5 = MagicMock()
    finding5.severity = "LOW"
    finding5.scan = scan2

    service.finding_repo.get_all.return_value = [
        finding1,
        finding2,
        finding3,
        finding4,
        finding5,
    ]

    result = service.global_risk_summary()

    assert result.total_findings == 5
    assert result.critical_count == 1
    assert result.high_count == 2
    assert result.medium_count == 1
    assert result.low_count == 1
    assert result.risk_score == 23
    assert result.repositories_at_risk == 2


def test_global_risk_summary_without_findings() -> None:
    session = MagicMock()

    service = DashboardService(
        session,
    )

    service.finding_repo = MagicMock()

    service.finding_repo.get_all.return_value = []

    result = service.global_risk_summary()

    assert result.total_findings == 0
    assert result.critical_count == 0
    assert result.high_count == 0
    assert result.medium_count == 0
    assert result.low_count == 0
    assert result.risk_score == 0
    assert result.repositories_at_risk == 0
