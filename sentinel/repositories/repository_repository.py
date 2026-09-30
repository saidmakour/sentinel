from sqlalchemy.orm import Session

from sentinel.models.repository import Repository


class RepositoryRepository:
    """
    Handles persistence of Repository objects.
    """

    def __init__(
        self,
        session: Session,
    ):
        self.session = session

    def create(
        self,
        repo: Repository,
    ) -> Repository:
        """
        Persist a new repository.
        """

        self.session.add(repo)
        self.session.flush()

        return repo

    def get_by_id(
        self,
        repository_id: int,
    ) -> Repository | None:
        """
        Return a repository by id.
        """

        return (
            self.session.query(Repository)
            .filter(
                Repository.id == repository_id,
            )
            .first()
        )

    def get_by_name(
        self,
        application_id: int,
        name: str,
    ) -> Repository | None:
        """
        Return repository by application and name.
        """

        return (
            self.session.query(Repository)
            .filter(
                Repository.application_id == application_id,
                Repository.name == name,
            )
            .first()
        )

    def list_by_application(
        self,
        application_id: int,
    ) -> list[Repository]:
        """
        Return repositories of an application.
        """

        return (
            self.session.query(Repository)
            .filter(
                Repository.application_id == application_id,
            )
            .order_by(
                Repository.name.asc(),
            )
            .all()
        )

    def get_by_path(
        self,
        application_id: int,
        path: str,
    ) -> Repository | None:
        """
        Return repository by local path.
        """

        return (
            self.session.query(Repository)
            .filter(
                Repository.application_id == application_id,
                Repository.local_path == path,
            )
            .first()
        )

    def get_all(self) -> list[Repository]:
        """
        Return all repositories.
        """

        return (
            self.session.query(Repository)
            .order_by(
                Repository.name.asc(),
            )
            .all()
        )

    def update(
        self,
        repo: Repository,
    ) -> Repository:
        """
        Update repository.
        """

        self.session.flush()

        return repo

    def delete(
        self,
        repo: Repository,
    ) -> None:
        """
        Delete repository.
        """

        self.session.delete(repo)
        self.session.flush()
