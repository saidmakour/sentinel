from unittest.mock import MagicMock

from sentinel.api.dashboard import DashboardAPI


def test_dashboard_summary():

    session = MagicMock()

    api = DashboardAPI(
        session,
    )

    api.service = MagicMock()

    expected = {
        "total_scans": 10,
    }

    api.service.summary.return_value = expected

    result = api.summary()

    assert result == expected
