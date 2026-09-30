from pathlib import Path
from unittest.mock import MagicMock

from sqlalchemy.orm import Session

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.dto.vulnerability_info import VulnerabilityInfo
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.provider import Provider
from sentinel.enums.severity import Severity
from sentinel.enums.source_type import SourceType
from sentinel.enums.vulnerability_status import VulnerabilityStatus
from sentinel.models.application import Application
from sentinel.models.repository import Repository
from sentinel.models.scan import Scan
from sentinel.models.vulnerability import Vulnerability
from sentinel.services.scan_service import ScanService


def test_run_scan_multiple_dependencies_and_findings(
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
        ScannedDependency(
            name="django",
            version="5.2.0",
            ecosystem=Ecosystem.PYPI,
            source="requirements.txt",
        ),
        ScannedDependency(
            name="urllib3",
            version="2.5.0",
            ecosystem=Ecosystem.PYPI,
            source="requirements.txt",
        ),
    ]

    engine.find_vulnerabilities.return_value = [
        VulnerabilityInfo(
            dependency_name="requests",
            dependency_version="2.32.0",
            ecosystem=Ecosystem.PYPI,
            identifier="CVE-2024-0001",
            aliases=["CVE-2024-0001"],
            sources=[Provider.OSV],
            summary="Requests vulnerability",
            severity=Severity.HIGH,
            cvss=8.7,
        ),
        VulnerabilityInfo(
            dependency_name="requests",
            dependency_version="2.32.0",
            ecosystem=Ecosystem.PYPI,
            identifier="GHSA-AAAA-BBBB-CCCC",
            aliases=["GHSA-AAAA-BBBB-CCCC"],
            sources=[Provider.GHSA],
            summary="Requests GHSA advisory",
            severity=Severity.MEDIUM,
            cvss=6.5,
        ),
        VulnerabilityInfo(
            dependency_name="django",
            dependency_version="5.2.0",
            ecosystem=Ecosystem.PYPI,
            identifier="CVE-2024-0002",
            aliases=["CVE-2024-0002"],
            sources=[Provider.NVD],
            summary="Django vulnerability",
            severity=Severity.CRITICAL,
            cvss=9.8,
        ),
    ]

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

    assert len(persisted_scan.dependencies) == 3

    assert len(persisted_scan.findings) == 3

    vulnerabilities = (
        db_session.query(Vulnerability)
        .filter(
            Vulnerability.repository_id == repository.id,
        )
        .all()
    )

    assert len(vulnerabilities) == 3

    identifiers = {
        vulnerability.identifier for vulnerability in vulnerabilities
    }

    assert identifiers == {
        "CVE-2024-0001",
        "GHSA-AAAA-BBBB-CCCC",
        "CVE-2024-0002",
    }

    assert all(
        vulnerability.status == VulnerabilityStatus.OPEN
        for vulnerability in vulnerabilities
    )

    engine.scan_dependencies.assert_called_once_with(
        "python",
        temp_project,
    )

    engine.find_vulnerabilities.assert_called_once()

    source_service.prepare.assert_called_once()
