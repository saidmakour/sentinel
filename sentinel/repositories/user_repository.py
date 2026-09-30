from sqlalchemy import func
from sqlalchemy import select
from sqlalchemy.orm import Session

from sentinel.models.user import User


class UserRepository:
    def __init__(
        self,
        session: Session,
    ) -> None:
        self.session = session

    def create(
        self,
        user: User,
    ) -> User:
        self.session.add(user)
        self.session.flush()

        return user

    def get_by_id(
        self,
        user_id: int,
    ) -> User | None:
        return self.session.get(
            User,
            user_id,
        )

    def get_by_username(
        self,
        username: str,
    ) -> User | None:
        statement = select(User).where(
            User.username == username,
        )

        return self.session.scalar(
            statement,
        )

    def list(self) -> list[User]:
        statement = select(User).order_by(
            User.id,
        )

        return list(
            self.session.scalars(
                statement,
            ).all(),
        )

    def update(
        self,
        user: User,
    ) -> User:
        self.session.flush()

        return user

    def delete(
        self,
        user: User,
    ) -> None:
        self.session.delete(user)
        self.session.flush()

    def count_active_admins(
        self,
    ) -> int:

        statement = (
            select(
                func.count(),
            )
            .select_from(
                User,
            )
            .where(
                User.is_admin.is_(True),
                User.is_active.is_(True),
            )
        )

        return (
            self.session.scalar(
                statement,
            )
            or 0
        )
