from sentinel.dto.severity_summary import SeveritySummary


def test_severity_summary_defaults():
    summary = SeveritySummary()

    assert summary.critical == 0
    assert summary.high == 0
    assert summary.medium == 0
    assert summary.low == 0
    assert summary.unknown == 0
    assert summary.total == 0


def test_severity_summary_total():
    summary = SeveritySummary(
        critical=1,
        high=2,
        medium=3,
        low=4,
        unknown=5,
    )

    assert summary.total == 15
