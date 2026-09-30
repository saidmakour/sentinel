from pathlib import Path
from unittest.mock import MagicMock

import pytest
from sqlalchemy.orm import Session

from sentinel.enums.scan_status import ScanStatus
from sentinel.enums.source_type import SourceType
from sentinel.models.application import Application
from sentinel.models.repository import Repository
from sentinel.models.scan import Scan
from sentinel.services.scan_service import ScanService


def test_run_scan_marks_scan_failed(
    db_session: Session,
    temp_project: Path,
) -> None:
    application = Application(
        name="Test Application",
    )

    db_session.add(application)
    db_session.flush()

    repository = Repository(
        application_id=application.id,
        name="test-repository",
        language="python",
        local_path=str(temp_project),
    )

    db_session.add(repository)
    db_session.commit()

    source_service = MagicMock()

    source_service.prepare.return_value = MagicMock(
        path=temp_project,
        source_type=SourceType.LOCAL,
        reference=None,
        branch=None,
        commit=None,
    )

    engine = MagicMock()

    engine.scan_dependencies.side_effect = RuntimeError(
        "Scanner crashed",
    )

    service = ScanService(
        session=db_session,
        engine=engine,
        source_service=source_service,
    )

    with pytest.raises(RuntimeError, match="Scanner crashed"):
        service.run(
            application_id=application.id,
            repository_name="test-repository",
        )

    db_session.expire_all()

    scan = db_session.query(Scan).order_by(Scan.id.desc()).one()

    assert scan.status == ScanStatus.FAILED
    assert scan.finished_at is not None
    assert scan.error_message == "Scanner crashed"

    assert len(scan.dependencies) == 0
    assert len(scan.findings) == 0

    engine.scan_dependencies.assert_called_once()

    engine.find_vulnerabilities.assert_not_called()

    source_service.prepare.assert_called_once()
