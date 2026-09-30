from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import Enum
from sqlalchemy import ForeignKey
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import UniqueConstraint
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

from sentinel.database.base import Base
from sentinel.enums.ecosystem import Ecosystem

if TYPE_CHECKING:
    from sentinel.models.scan import Scan


class Dependency(Base):
    __tablename__ = "dependencies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    version: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    ecosystem: Mapped[Ecosystem] = mapped_column(
        Enum(Ecosystem),
        nullable=False,
        default=Ecosystem.PYPI,
    )

    scan: Mapped[Scan] = relationship(
        back_populates="dependencies",
        lazy="selectin",
    )

    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "name",
            "version",
            name="uq_dependency_scan_name_version",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<Dependency(id={self.id}, "
            f"name='{self.name}', "
            f"version='{self.version}')>"
        )

    @property
    def purl(self) -> str:
        return f"pkg:{self.ecosystem}/{self.name}@{self.version}"

    @property
    def display_name(self) -> str:
        return f"{self.name}=={self.version}"
