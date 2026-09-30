from __future__ import annotations

from datetime import date
from typing import TYPE_CHECKING

from sqlalchemy import JSON
from sqlalchemy import Boolean
from sqlalchemy import Date
from sqlalchemy import Enum
from sqlalchemy import Float
from sqlalchemy import ForeignKey
from sqlalchemy import String
from sqlalchemy import UniqueConstraint
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

from sentinel.database.base import Base
from sentinel.dto.remediation_info import RemediationData
from sentinel.enums.ecosystem import Ecosystem
from sentinel.enums.severity import Severity
from sentinel.enums.vulnerability_status import VulnerabilityStatus

if TYPE_CHECKING:
    from sentinel.models.scan import Scan


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)

    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id"),
        nullable=False,
        index=True,
    )

    dependency_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    dependency_version: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    ecosystem: Mapped[Ecosystem] = mapped_column(
        Enum(Ecosystem),
        nullable=False,
    )

    identifier: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    aliases: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )

    severity: Mapped[Severity] = mapped_column(
        Enum(Severity),
        nullable=False,
    )

    sources: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )

    cvss: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    status: Mapped[VulnerabilityStatus] = mapped_column(
        Enum(VulnerabilityStatus),
        nullable=False,
        default=VulnerabilityStatus.UNKNOWN,
    )

    summary: Mapped[str] = mapped_column(
        String(1000),
        nullable=False,
        default="",
    )

    remediation: Mapped[RemediationData | None] = mapped_column(
        JSON,
        nullable=True,
    )

    fixed_versions: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )

    scan: Mapped[Scan] = relationship(back_populates="findings")

    # CISA KEV
    known_exploited: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    kev_date_added: Mapped[date | None] = mapped_column(
        Date,
        nullable=True,
    )

    kev_vendor: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    kev_product: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    kev_required_action: Mapped[str | None] = mapped_column(
        String(1000),
        nullable=True,
    )

    kev_known_ransomware: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    # VulnCheck
    vulncheck_known_exploited: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    vulncheck_date_added: Mapped[date | None] = mapped_column(
        Date,
        nullable=True,
    )

    vulncheck_cisa_date_added: Mapped[date | None] = mapped_column(
        Date,
        nullable=True,
    )

    vulncheck_due_date: Mapped[date | None] = mapped_column(
        Date,
        nullable=True,
    )

    vulncheck_vendor: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    vulncheck_product: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    vulncheck_required_action: Mapped[str | None] = mapped_column(
        String(1000),
        nullable=True,
    )

    vulncheck_known_ransomware: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    vulncheck_reported_exploited_by_canaries: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    # EPSS
    epss_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    epss_percentile: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "dependency_name",
            "dependency_version",
            "identifier",
            name="uq_finding_scan_dependency_identifier",
        ),
    )

    @property
    def comparison_key(
        self,
    ) -> tuple[str, str, str]:
        """
        Return the business key used to compare findings between scans.
        """

        return (
            self.dependency_name,
            self.dependency_version,
            self.identifier,
        )
