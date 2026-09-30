from __future__ import annotations

from datetime import UTC
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean
from sqlalchemy import DateTime
from sqlalchemy import Enum
from sqlalchemy import ForeignKey
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import UniqueConstraint
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

from sentinel.database.base import Base
from sentinel.enums.git_auth_method import GitAuthMethod

if TYPE_CHECKING:
    from sentinel.models.application import Application
    from sentinel.models.scan import Scan
    from sentinel.models.vulnerability import Vulnerability


class Repository(Base):
    __tablename__ = "repositories"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    application_id: Mapped[int] = mapped_column(
        ForeignKey("applications.id"),
        nullable=False,
        index=True,
    )

    name: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
    )

    local_path: Mapped[str] = mapped_column(
        String(500),
        default="",
        nullable=False,
    )

    remote_url: Mapped[str] = mapped_column(
        String(500),
        default="",
        nullable=False,
    )

    auth_method: Mapped[GitAuthMethod] = mapped_column(
        Enum(GitAuthMethod),
        default=GitAuthMethod.NONE,
        nullable=False,
    )

    credentials_ref: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    default_branch: Mapped[str] = mapped_column(
        String(100),
        default="main",
    )

    language: Mapped[str] = mapped_column(
        String(50),
        default="python",
    )

    package_manager: Mapped[str] = mapped_column(
        String(50),
        default="pip",
    )

    enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    application: Mapped[Application] = relationship(
        "Application",
        back_populates="repositories",
    )

    scans: Mapped[list[Scan]] = relationship(
        "Scan",
        back_populates="repository",
        cascade="all, delete-orphan",
    )
    vulnerabilities: Mapped[list[Vulnerability]] = relationship(
        "Vulnerability",
        back_populates="repository",
        cascade="all, delete-orphan",
    )
    __table_args__ = (
        UniqueConstraint(
            "application_id",
            "name",
            name="uq_repository_application_name",
        ),
        UniqueConstraint(
            "application_id",
            "local_path",
            name="uq_repository_application_path",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<Repository("
            f"id={self.id}, "
            f"name='{self.name}', "
            f"application_id={self.application_id})>"
        )

    @property
    def scan_count(self) -> int:
        return len(self.scans)

    @property
    def is_remote(self) -> bool:
        return bool(self.remote_url)

    def disable(self) -> None:
        self.enabled = False

    def enable(self) -> None:
        self.enabled = True
