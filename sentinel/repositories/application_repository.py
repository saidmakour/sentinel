from sqlalchemy.orm import Session

from sentinel.models.application import Application


class ApplicationRepository:
    def __init__(self, session: Session):
        self.session = session

    def create(self, application: Application) -> Application:
        self.session.add(application)
        self.session.flush()

        return application

    def get_by_id(
        self,
        application_id: int,
    ) -> Application | None:
        """
        Return an application by id.
        """

        return (
            self.session.query(Application)
            .filter(
                Application.id == application_id,
            )
            .first()
        )

    def get_by_name(self, name: str) -> Application | None:
        return (
            self.session.query(Application)
            .filter(Application.name == name)
            .first()
        )

    def list_all(self) -> list[Application]:
        return self.session.query(Application).all()

    def list_enabled(self) -> list[Application]:
        return (
            self.session.query(Application)
            .filter(
                Application.enabled.is_(True),
            )
            .all()
        )

    def exists(self, name: str) -> bool:
        return (
            self.session.query(
                Application.id,
            )
            .filter(
                Application.name == name,
            )
            .first()
            is not None
        )

    def update(
        self,
        application: Application,
    ) -> Application:
        """
        Update an application.
        """

        self.session.flush()

        return application

    def delete_by_name(self, name: str) -> None:
        app = self.get_by_name(name)
        if app:
            self.session.delete(app)
            self.session.flush()

    def delete(
        self,
        application: Application,
    ) -> None:
        """
        Delete an application.
        """

        self.session.delete(application)
        self.session.flush()
