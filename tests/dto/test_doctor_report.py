from sentinel.dto.doctor_check import DoctorCheck
from sentinel.dto.doctor_report import DoctorReport
from sentinel.enums.doctor_status import DoctorStatus


def test_doctor_report_can_be_created() -> None:
    report = DoctorReport(
        checks=[],
    )

    assert report.checks == []


def test_total_returns_zero_for_empty_report() -> None:
    report = DoctorReport(
        checks=[],
    )

    assert report.total == 0


def test_passed_returns_zero_for_empty_report() -> None:
    report = DoctorReport(
        checks=[],
    )

    assert report.passed == 0


def test_warnings_returns_zero_for_empty_report() -> None:
    report = DoctorReport(
        checks=[],
    )

    assert report.warnings == 0


def test_failed_returns_zero_for_empty_report() -> None:
    report = DoctorReport(
        checks=[],
    )

    assert report.failed == 0


def test_statistics_are_calculated() -> None:
    report = DoctorReport(
        checks=[
            DoctorCheck(
                "Database",
                DoctorStatus.PASS,
                "OK",
            ),
            DoctorCheck(
                "Workspace",
                DoctorStatus.PASS,
                "OK",
            ),
            DoctorCheck(
                "Git",
                DoctorStatus.WARNING,
                "Missing executable",
            ),
            DoctorCheck(
                "Providers",
                DoctorStatus.FAIL,
                "OSV unavailable",
            ),
        ],
    )

    assert report.total == 4
    assert report.passed == 2
    assert report.warnings == 1
    assert report.failed == 1


def test_report_with_only_passed_checks() -> None:
    report = DoctorReport(
        checks=[
            DoctorCheck(
                "Database",
                DoctorStatus.PASS,
                "OK",
            ),
            DoctorCheck(
                "Workspace",
                DoctorStatus.PASS,
                "OK",
            ),
        ],
    )

    assert report.total == 2
    assert report.passed == 2
    assert report.warnings == 0
    assert report.failed == 0


def test_report_with_only_failed_checks() -> None:
    report = DoctorReport(
        checks=[
            DoctorCheck(
                "Database",
                DoctorStatus.FAIL,
                "KO",
            ),
            DoctorCheck(
                "Workspace",
                DoctorStatus.FAIL,
                "KO",
            ),
        ],
    )

    assert report.total == 2
    assert report.passed == 0
    assert report.warnings == 0
    assert report.failed == 2
