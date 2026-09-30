from unittest.mock import MagicMock

import pytest

from sentinel.exceptions.scan import ScanNotFoundError
from sentinel.services.scan_history_service import ScanHistoryService


def test_compare_with_previous_raises_when_scan_not_found():

    session = MagicMock()

    service = ScanHistoryService(session)

    service.scan_repo.get_by_id = MagicMock(
        return_value=None,
    )

    with pytest.raises(ScanNotFoundError):
        service.compare_with_previous(1)
