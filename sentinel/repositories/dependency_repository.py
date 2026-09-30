from sqlalchemy.orm import Session

from sentinel.dto.scanned_dependency import ScannedDependency
from sentinel.models.dependency import Dependency


class DependencyRepository:
    """
    Handles persistence of Dependency objects.
    """

    def __init__(self, session: Session):
        self.session = session

    def add_many(
        self,
        dependencies: list[ScannedDependency],
        scan_id: int,
    ) -> None:
        """
        Persist scanned dependencies.
        """

        models = [
            Dependency(
                scan_id=scan_id,
                name=dependency.name,
                version=dependency.version,
                ecosystem=dependency.ecosystem,
            )
            for dependency in dependencies
        ]

        self.session.add_all(models)
        self.session.flush()

    def list_all(self) -> list[Dependency]:
        return self.session.query(Dependency).all()

    def list_by_scan(
        self,
        scan_id: int,
    ) -> list[ScannedDependency]:

        dependencies = (
            self.session.query(Dependency)
            .filter(
                Dependency.scan_id == scan_id,
            )
            .all()
        )

        return [
            ScannedDependency(
                name=dependency.name,
                version=dependency.version,
                ecosystem=dependency.ecosystem,
                source="database",
                priority=0,
            )
            for dependency in dependencies
        ]
