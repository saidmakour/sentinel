from pathlib import Path
from unittest.mock import MagicMock

from sqlalchemy.orm import Session

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.scan_status import ScanStatus
from sentinel.enums.source_type import SourceType
from sentinel.models.application import Application
from sentinel.models.repository import Repository
from sentinel.models.scan import Scan
from sentinel.models.vulnerability import Vulnerability
from sentinel.services.scan_service import ScanService


def test_run_scan_without_vulnerabilities(
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

    engine.scan_dependencies.return_value = [
        ScannedDependency(
            name="requests",
            version="2.32.0",
            ecosystem=Ecosystem.PYPI,
            source="requirements.txt",
        ),
    ]

    # aucune vulnérabilité
    engine.find_vulnerabilities.return_value = []

    service = ScanService(
        session=db_session,
        engine=engine,
        source_service=source_service,
    )

    scan = service.run(
        application_id=application.id,
        repository_name="test-repository",
    )

    db_session.expire_all()

    persisted_scan = db_session.get(
        Scan,
        scan.id,
    )

    assert persisted_scan is not None

    assert persisted_scan.status == ScanStatus.SUCCESS
    assert persisted_scan.finished_at is not None
    assert persisted_scan.duration_seconds is not None

    # dépendance persistée
    assert len(persisted_scan.dependencies) == 1

    dependency = persisted_scan.dependencies[0]

    assert dependency.name == "requests"
    assert dependency.version == "2.32.0"

    # aucun finding
    assert len(persisted_scan.findings) == 0

    # aucune vulnérabilité métier
    assert db_session.query(Vulnerability).count() == 0

    engine.scan_dependencies.assert_called_once()

    engine.find_vulnerabilities.assert_called_once()

    source_service.prepare.assert_called_once()
