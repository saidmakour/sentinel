import json
from typing import Annotated

from fastapi import APIRouter
from fastapi import Depends
from fastapi import Query
from fastapi.responses import HTMLResponse
from fastapi.responses import JSONResponse
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from sentinel.api.dependencies import get_session
from sentinel.api.mappers.risk_history_mapper import risk_history_to_schema
from sentinel.api.mappers.risk_trend_mapper import risk_trend_to_schema
from sentinel.api.mappers.scan_comparison_mapper import (
    scan_comparison_to_schema,
)
from sentinel.api.mappers.scan_mapper import scan_to_summary_schema
from sentinel.api.mappers.scan_report_mapper import scan_report_to_schema
from sentinel.api.schemas.risk_history import RiskHistoryPointSchema
from sentinel.api.schemas.risk_trend import RiskTrendSchema
from sentinel.api.schemas.scan import ScanSummarySchema
from sentinel.api.schemas.scan_comparison import ScanComparisonSchema
from sentinel.api.schemas.scan_report import ScanReportSchema
from sentinel.reports.registry import ReportRendererRegistry
from sentinel.repositories.scan_repository import ScanRepository
from sentinel.security.dependencies import CurrentUser
from sentinel.services.risk_history_service import RiskHistoryService
from sentinel.services.risk_trend_service import RiskTrendService
from sentinel.services.scan_history_service import ScanHistoryService
from sentinel.services.scan_report_service import ScanReportService

router = APIRouter(
    prefix="/scans",
    tags=["scans"],
)

SessionDep = Annotated[
    Session,
    Depends(get_session),
]


@router.get(
    "/{scan_id}/comparison",
    response_model=ScanComparisonSchema | None,
)
def compare_scan(
    current_user: CurrentUser,
    scan_id: int,
    session: SessionDep,
) -> ScanComparisonSchema | None:

    service = ScanHistoryService(
        session,
    )

    comparison = service.compare_with_previous(
        scan_id,
    )

    if comparison is None:
        return None

    return scan_comparison_to_schema(
        comparison,
    )


@router.get(
    "/repositories/{repository_id}/history",
    response_model=list[ScanSummarySchema],
)
def list_repository_scans(
    current_user: CurrentUser,
    repository_id: int,
    session: SessionDep,
) -> list[ScanSummarySchema]:

    repository = ScanRepository(
        session,
    )

    scans = repository.list_by_repository(
        repository_id,
    )

    return [scan_to_summary_schema(scan) for scan in scans]


@router.get(
    "/repositories/{repository_id}/risk-history",
    response_model=list[RiskHistoryPointSchema],
)
def risk_history(
    current_user: CurrentUser,
    repository_id: int,
    session: SessionDep,
) -> list[RiskHistoryPointSchema]:

    service = RiskHistoryService(
        session,
    )

    history = service.get_history(
        repository_id,
    )

    return risk_history_to_schema(
        history,
    )


@router.get(
    "/repositories/{repository_id}/risk-trend",
    response_model=RiskTrendSchema,
)
def risk_trend(
    current_user: CurrentUser,
    repository_id: int,
    session: SessionDep,
) -> RiskTrendSchema:

    service = RiskTrendService(
        session,
    )

    result = service.get_trend(
        repository_id,
    )

    return risk_trend_to_schema(
        result,
    )


@router.get(
    "/{scan_id}/report/export",
    response_model=None,
)
def export_scan_report(
    current_user: CurrentUser,
    scan_id: int,
    session: SessionDep,
    format: str = Query(
        default="json",
    ),
) -> JSONResponse | PlainTextResponse | HTMLResponse:

    service = ScanReportService(
        session,
    )

    report = service.get_report(
        scan_id,
    )

    renderer = ReportRendererRegistry().create(
        format,
    )

    content = renderer.render(
        report,
    )

    match format.lower():
        case "html":
            return HTMLResponse(
                content=content,
            )

        case "json" | "sarif":
            return JSONResponse(
                content=json.loads(content),
            )

        case "markdown":
            return PlainTextResponse(
                content=content,
                media_type="text/markdown",
            )

        case _:
            return PlainTextResponse(
                content=content,
            )


@router.get(
    "/{scan_id}/report",
    response_model=ScanReportSchema,
)
def get_scan_report(
    current_user: CurrentUser,
    scan_id: int,
    session: SessionDep,
) -> ScanReportSchema:

    service = ScanReportService(
        session,
    )

    report = service.get_report(
        scan_id,
    )

    return scan_report_to_schema(
        report,
    )
