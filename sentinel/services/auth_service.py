from sqlalchemy.orm import Session

from sentinel.exceptions.auth import LastAdminError
from sentinel.exceptions.auth import UserAlreadyExistsError
from sentinel.exceptions.auth import UserNotFoundError
from sentinel.models.user import User
from sentinel.repositories.user_repository import UserRepository
from sentinel.security.password import hash_password
from sentinel.security.password import verify_password


class AuthService:
    def __init__(
        self,
        session: Session,
    ) -> None:
        self.session = session
        self.user_repository = UserRepository(
            session,
        )

    def create_user(
        self,
        username: str,
        password: str,
        is_admin: bool = False,
    ) -> User:

        username = username.strip()

        existing_user = self.user_repository.get_by_username(
            username,
        )

        if existing_user is not None:
            raise UserAlreadyExistsError(
                f"User '{username}' already exists",
            )

        user = User(
            username=username,
            password_hash=hash_password(password),
            is_active=True,
            is_admin=is_admin,
        )

        user = self.user_repository.create(
            user,
        )

        self.session.commit()

        return user

    def authenticate(
        self,
        username: str,
        password: str,
    ) -> User | None:

        user = self.user_repository.get_by_username(
            username,
        )

        if user is None:
            return None

        if not user.is_active:
            return None

        if not verify_password(
            password,
            user.password_hash,
        ):
            return None

        return user

    def list_users(
        self,
    ) -> list[User]:

        return self.user_repository.list()

    def require_by_username(
        self,
        username: str,
    ) -> User:

        user = self.user_repository.get_by_username(
            username,
        )

        if user is None:
            raise UserNotFoundError(
                f"User '{username}' not found",
            )

        return user

    def change_password(
        self,
        username: str,
        password: str,
    ) -> User:

        user = self.require_by_username(
            username,
        )

        user.password_hash = hash_password(
            password,
        )

        user = self.user_repository.update(
            user,
        )

        self.session.commit()

        return user

    def promote_user(
        self,
        username: str,
    ) -> User:

        user = self.require_by_username(
            username,
        )

        user.is_admin = True

        user = self.user_repository.update(
            user,
        )

        self.session.commit()

        return user

    def demote_user(
        self,
        username: str,
    ) -> User:

        user = self.require_by_username(
            username,
        )

        if user.is_admin:
            self._ensure_not_last_admin(
                user,
            )

        user.is_admin = False

        user = self.user_repository.update(
            user,
        )

        self.session.commit()

        return user

    def enable_user(
        self,
        username: str,
    ) -> User:

        user = self.require_by_username(
            username,
        )

        user.is_active = True

        user = self.user_repository.update(
            user,
        )

        self.session.commit()

        return user

    def disable_user(
        self,
        username: str,
    ) -> User:

        user = self.require_by_username(
            username,
        )

        if user.is_admin and user.is_active:
            self._ensure_not_last_admin(
                user,
            )

        user.is_active = False

        user = self.user_repository.update(
            user,
        )

        self.session.commit()

        return user

    def delete_user(
        self,
        username: str,
    ) -> None:

        user = self.require_by_username(
            username,
        )

        if user.is_admin:
            self._ensure_not_last_admin(
                user,
            )

        self.user_repository.delete(
            user,
        )

        self.session.commit()

    def _ensure_not_last_admin(
        self,
        user: User,
    ) -> None:

        if (
            user.is_admin
            and user.is_active
            and self.user_repository.count_active_admins() <= 1
        ):
            raise LastAdminError(
                "Cannot remove the last active administrator",
            )
