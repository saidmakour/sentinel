from sqlalchemy.orm import Session

from sentinel.models.scan import Scan


class ScanRepository:
    """
    Handles persistence of Scan objects.
    """

    def __init__(self, session: Session):
        self.session = session

    def create(self, scan: Scan) -> Scan:
        """
        Persist a new scan.
        """

        self.session.add(scan)
        self.session.flush()

        return scan

    def get_by_id(
        self,
        scan_id: int,
    ) -> Scan | None:
        """
        Return a scan by id.
        """

        return self.session.query(Scan).filter(Scan.id == scan_id).first()

    def list_by_repository(
        self,
        repository_id: int,
    ) -> list[Scan]:
        """
        Return all scans of a repository.
        """

        return (
            self.session.query(Scan)
            .filter(
                Scan.repository_id == repository_id,
            )
            .order_by(
                Scan.started_at.desc(),
            )
            .all()
        )

    def latest_by_repository(
        self,
        repository_id: int,
    ) -> Scan | None:
        """
        Return latest scan of a repository.
        """

        return (
            self.session.query(Scan)
            .filter(
                Scan.repository_id == repository_id,
            )
            .order_by(
                Scan.started_at.desc(),
            )
            .first()
        )

    def get_all(self) -> list[Scan]:
        """
        Return all scans.
        """

        return (
            self.session.query(Scan)
            .order_by(
                Scan.started_at.desc(),
            )
            .all()
        )

    def get_previous_scan(
        self,
        scan: Scan,
    ) -> Scan | None:
        """
        Return the scan immediately preceding the given scan
        for the same repository.
        """

        return (
            self.session.query(Scan)
            .filter(
                Scan.repository_id == scan.repository_id,
                Scan.started_at < scan.started_at,
            )
            .order_by(
                Scan.started_at.desc(),
                Scan.id.desc(),
            )
            .first()
        )
