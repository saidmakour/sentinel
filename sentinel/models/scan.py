from __future__ import annotations

from datetime import UTC
from datetime import datetime
from datetime import timedelta
from typing import TYPE_CHECKING

from sqlalchemy import DateTime
from sqlalchemy import Enum
from sqlalchemy import ForeignKey
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

from sentinel.config.settings import settings
from sentinel.database.base import Base
from sentinel.enums.scan_status import ScanStatus
from sentinel.enums.source_type import SourceType

if TYPE_CHECKING:
    from sentinel.models.dependency import Dependency
    from sentinel.models.finding import Finding
    from sentinel.models.repository import Repository


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    repository_id: Mapped[int] = mapped_column(
        ForeignKey("repositories.id"),
        nullable=False,
        index=True,
    )
    profile_name: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="default",
    )
    engine_version: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default=settings.app_version,
    )

    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus),
        default=ScanStatus.STARTED,
        nullable=False,
        index=True,
    )

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    duration_seconds: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    repository: Mapped[Repository] = relationship(
        back_populates="scans", lazy="selectin"
    )

    dependencies: Mapped[list[Dependency]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    findings: Mapped[list[Finding]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    source_type: Mapped[SourceType] = mapped_column(
        Enum(SourceType),
        default=SourceType.LOCAL,
        nullable=False,
    )

    source_reference: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )
    source_branch: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    source_commit: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    error_message: Mapped[str | None] = mapped_column(
        String(2000),
        nullable=True,
    )

    def __repr__(self) -> str:
        return (
            f"<Scan(id={self.id}, "
            f"repository_id={self.repository_id}, "
            f"status={self.status.value})>"
        )

    def mark_finished(self, duration_seconds: int) -> None:
        if self.is_finished:
            return
        self.status = ScanStatus.SUCCESS
        self.finished_at = datetime.now(UTC)
        self.duration_seconds = duration_seconds

    def mark_failed(self, error_message: str | None = None) -> None:
        self.status = ScanStatus.FAILED
        self.finished_at = datetime.now(UTC)
        self.error_message = error_message

    @property
    def is_finished(self) -> bool:
        return self.status in (
            ScanStatus.SUCCESS,
            ScanStatus.FAILED,
        )

    @property
    def dependency_count(self) -> int:
        return len(self.dependencies)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def duration(self) -> timedelta | None:
        if self.duration_seconds is None:
            return None

        return timedelta(seconds=self.duration_seconds)
