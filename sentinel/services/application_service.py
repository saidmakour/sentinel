from __future__ import annotations

from sqlalchemy.orm import Session

from sentinel.enums.criticality import Criticality
from sentinel.exceptions.application import ApplicationAlreadyExistsError
from sentinel.exceptions.application import ApplicationLevelCriticalityError
from sentinel.exceptions.application import ApplicationNameNotEmptyError
from sentinel.exceptions.application import ApplicationNotFoundError
from sentinel.models.application import Application
from sentinel.repositories.application_repository import ApplicationRepository


class ApplicationService:
    def __init__(
        self,
        session: Session,
    ) -> None:
        self.session = session
        self.repo = ApplicationRepository(
            session,
        )

    def create(
        self,
        name: str,
        description: str = "",
        owner: str = "",
        criticality: int = 3,
    ) -> Application:

        name = (name or "").strip()
        description = (description or "").strip()
        owner = (owner or "").strip()

        if not name:
            raise ApplicationNameNotEmptyError(
                "Application name cannot be empty",
            )

        try:
            criticality_value = Criticality(
                criticality,
            )
        except ValueError as exc:
            raise ApplicationLevelCriticalityError(
                f"Invalid criticality: {criticality}",
            ) from exc

        if self.repo.exists(
            name,
        ):
            raise ApplicationAlreadyExistsError(
                f"Application '{name}' already exists",
            )

        application = Application(
            name=name,
            description=description,
            owner=owner,
            criticality=criticality_value,
        )

        self.repo.create(
            application,
        )

        self.session.commit()

        return application

    def list_all(
        self,
    ) -> list[Application]:

        return self.repo.list_all()

    def list_enabled(
        self,
    ) -> list[Application]:

        return self.repo.list_enabled()

    def get_by_id(
        self,
        application_id: int,
    ) -> Application | None:

        return self.repo.get_by_id(
            application_id,
        )

    def get_by_name(
        self,
        name: str,
    ) -> Application | None:

        return self.repo.get_by_name(
            name,
        )

    def require_by_id(
        self,
        application_id: int,
    ) -> Application:

        application = self.get_by_id(
            application_id,
        )

        if application is None:
            raise ApplicationNotFoundError(
                f"Application '{application_id}' not found",
            )

        return application

    def update(
        self,
        application_id: int,
        name: str | None = None,
        description: str | None = None,
        owner: str | None = None,
        criticality: int | None = None,
    ) -> Application:

        application = self.require_by_id(
            application_id,
        )

        if name is not None:
            name = name.strip()

            if not name:
                raise ApplicationNameNotEmptyError(
                    "Application name cannot be empty",
                )

            if name != application.name and self.repo.exists(name):
                raise ApplicationAlreadyExistsError(
                    f"Application '{name}' already exists",
                )

            application.name = name

        if description is not None:
            application.description = description.strip()

        if owner is not None:
            application.owner = owner.strip()

        if criticality is not None:
            try:
                application.criticality = Criticality(
                    criticality,
                )
            except ValueError as exc:
                raise ApplicationLevelCriticalityError(
                    f"Invalid criticality: {criticality}",
                ) from exc

        application = self.repo.update(
            application,
        )

        self.session.commit()

        return application

    def delete(
        self,
        name: str,
    ) -> None:

        application = self.repo.get_by_name(
            name,
        )

        if application is None:
            raise ApplicationNotFoundError(
                f"Application '{name}' not found",
            )

        self.repo.delete(
            application,
        )

        self.session.commit()

    def delete_by_id(
        self,
        application_id: int,
    ) -> None:

        application = self.require_by_id(
            application_id,
        )

        self.repo.delete(
            application,
        )

        self.session.commit()
