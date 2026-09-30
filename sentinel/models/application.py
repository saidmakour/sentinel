from __future__ import annotations

from datetime import UTC
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean
from sqlalchemy import DateTime
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

from sentinel.database.base import Base
from sentinel.enums.criticality import Criticality

if TYPE_CHECKING:
    from sentinel.models.repository import Repository


class Application(Base):
    __tablename__ = "applications"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    name: Mapped[str] = mapped_column(
        String(200),
        unique=True,
        nullable=False,
        index=True,
    )

    description: Mapped[str] = mapped_column(
        String(1000),
        nullable=False,
        default="",
    )

    owner: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
        default="",
    )

    criticality: Mapped[Criticality] = mapped_column(
        Integer,
        nullable=False,
        default=Criticality.HIGH,
    )

    enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    repositories: Mapped[list[Repository]] = relationship(
        "Repository",
        back_populates="application",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return (
            f"<Application("
            f"id={self.id}, "
            f"name='{self.name}', "
            f"enabled={self.enabled})>"
        )

    def disable(self) -> None:
        self.enabled = False

    def enable(self) -> None:
        self.enabled = True

    @property
    def repository_count(self) -> int:
        return len(self.repositories)
