from __future__ import annotations

from datetime import UTC
from datetime import datetime

from sqlalchemy.orm import Session

from sentinel.engine.engine import SentinelEngine
from sentinel.enums.scan_status import ScanStatus
from sentinel.exceptions.repository import RepositoryNotFoundError
from sentinel.log import get_logger
from sentinel.models.repository import Repository
from sentinel.models.scan import Scan
from sentinel.profiles.base import BaseProfile
from sentinel.profiles.registry import ProfileRegistry
from sentinel.repositories.dependency_repository import DependencyRepository
from sentinel.repositories.finding_repository import FindingRepository
from sentinel.repositories.repository_repository import RepositoryRepository
from sentinel.repositories.scan_repository import ScanRepository
from sentinel.services.vulnerability_service import VulnerabilityService
from sentinel.sources.service import SourceService

logger = get_logger(__name__)


class ScanService:
    def __init__(
        self,
        session: Session,
        engine: SentinelEngine | None = None,
        source_service: SourceService | None = None,
        profile_registry: ProfileRegistry | None = None,
        vulnerability_service: VulnerabilityService | None = None,
    ) -> None:
        self.session = session

        self.repo_repo = RepositoryRepository(session)
        self.scan_repo = ScanRepository(session)
        self.dependency_repo = DependencyRepository(session)
        self.finding_repo = FindingRepository(session)
        self.engine = engine or SentinelEngine()
        self.source_service = source_service or SourceService()
        self.profile_registry = profile_registry or ProfileRegistry()
        self.vulnerability_service = (
            vulnerability_service or VulnerabilityService(session)
        )

    def run(
        self,
        application_id: int,
        repository_name: str,
        profile_name: str = "default",
        forge_name: str | None = None,
    ) -> Scan:

        logger.info(
            "Starting scan: repository=%s profile=%s",
            repository_name,
            profile_name,
        )

        repo = self._get_repository(
            application_id,
            repository_name,
        )

        profile = self.profile_registry.create(
            profile_name,
        )

        scan = self._create_scan(
            repo,
            profile_name,
        )

        self.session.commit()

        try:
            self._execute_scan(
                repo,
                scan,
                profile,
                forge_name,
            )

            self._finish_scan(
                scan,
            )

            self.session.commit()

            logger.info(
                "Scan completed: scan_id=%s repository=%s",
                scan.id,
                repo.name,
            )

            return scan

        except Exception as exc:
            logger.exception(
                "Scan failed: scan_id=%s repository=%s",
                scan.id,
                repo.name,
            )

            self._fail_scan(
                scan,
                exc,
            )

            raise

    def _create_scan(
        self,
        repo: Repository,
        profile_name: str,
    ) -> Scan:

        scan = Scan(
            repository_id=repo.id,
            profile_name=profile_name,
            status=ScanStatus.STARTED,
            started_at=datetime.now(UTC),
        )

        return self.scan_repo.create(
            scan,
        )

    def _execute_scan(
        self,
        repo: Repository,
        scan: Scan,
        profile: BaseProfile,
        forge_name: str | None = None,
    ) -> None:

        logger.debug(
            "Preparing source: repository=%s",
            repo.name,
        )

        source = self.source_service.prepare(
            repo,
            forge_name=forge_name,
        )

        scan.source_type = source.source_type
        scan.source_reference = source.reference
        scan.source_branch = source.branch
        scan.source_commit = source.commit

        logger.debug(
            "Scanning source: path=%s",
            source.path,
        )

        dependencies = self.engine.scan_dependencies(
            repo.language,
            source.path,
        )

        logger.info(
            "Dependencies discovered: scan_id=%s count=%d",
            scan.id,
            len(dependencies),
        )

        self.dependency_repo.add_many(
            dependencies,
            scan.id,
        )

        findings = self.engine.find_vulnerabilities(
            dependencies,
            profile,
        )

        logger.info(
            "Vulnerabilities discovered: scan_id=%s count=%d",
            scan.id,
            len(findings),
        )

        self.finding_repo.add_many(
            findings,
            scan.id,
        )

        for finding in findings:
            self.vulnerability_service.sync(
                repo.id,
                finding.identifier,
            )

        identifiers = {finding.identifier for finding in findings}

        self.vulnerability_service.resolve_missing(
            repository_id=repo.id,
            identifiers=identifiers,
        )

    def _get_repository(
        self,
        application_id: int,
        repository_name: str,
    ) -> Repository:

        repo = self.repo_repo.get_by_name(
            application_id,
            repository_name,
        )

        if repo is None:
            raise RepositoryNotFoundError(
                f"Repository '{repository_name}' not found",
            )

        logger.debug(
            "Repository found: name=%s id=%s",
            repo.name,
            repo.id,
        )

        return repo

    def _calculate_duration(
        self,
        started_at: datetime,
    ) -> int:

        if started_at.tzinfo is None:
            started_at = started_at.replace(
                tzinfo=UTC,
            )

        return int(
            (datetime.now(UTC) - started_at).total_seconds(),
        )

    def _finish_scan(
        self,
        scan: Scan,
    ) -> None:

        duration = self._calculate_duration(
            scan.started_at,
        )

        scan.mark_finished(
            duration,
        )

        logger.debug(
            "Scan marked as finished: scan_id=%s duration=%ss",
            scan.id,
            duration,
        )

    def _fail_scan(
        self,
        scan: Scan,
        exc: Exception,
    ) -> None:

        self.session.rollback()

        scan.mark_failed(
            str(exc),
        )

        self.session.add(
            scan,
        )

        self.session.commit()
