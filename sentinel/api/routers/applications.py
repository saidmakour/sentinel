from typing import Annotated

from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Response
from sqlalchemy.orm import Session

from sentinel.api.dependencies import get_session
from sentinel.api.schemas.application import ApplicationCreate
from sentinel.api.schemas.application import ApplicationResponse
from sentinel.api.schemas.application import ApplicationUpdate
from sentinel.security.dependencies import CurrentAdmin
from sentinel.security.dependencies import CurrentUser
from sentinel.services.application_service import ApplicationService

router = APIRouter(
    prefix="/applications",
    tags=["Applications"],
)

SessionDep = Annotated[
    Session,
    Depends(get_session),
]


@router.get(
    "",
    response_model=list[ApplicationResponse],
)
def list_applications(
    current_user: CurrentUser,
    session: SessionDep,
) -> list[ApplicationResponse]:

    service = ApplicationService(session)

    return [
        ApplicationResponse.model_validate(app) for app in service.list_all()
    ]


@router.get(
    "/{application_id}",
    response_model=ApplicationResponse,
)
def get_application(
    current_user: CurrentUser,
    application_id: int,
    session: SessionDep,
) -> ApplicationResponse:

    service = ApplicationService(session)

    application = service.get_by_id(
        application_id,
    )
    if application is None:
        raise HTTPException(
            status_code=404,
            detail="Application not found",
        )
    return ApplicationResponse.model_validate(
        application,
    )


@router.post(
    "",
    response_model=ApplicationResponse,
    status_code=201,
)
def create_application(
    current_user: CurrentAdmin,
    payload: ApplicationCreate,
    session: SessionDep,
) -> ApplicationResponse:

    service = ApplicationService(session)

    application = service.create(
        name=payload.name,
        description=payload.description or "",
        owner=payload.owner or "",
        criticality=payload.criticality,
    )

    return ApplicationResponse.model_validate(
        application,
    )


@router.patch(
    "/{application_id}",
    response_model=ApplicationResponse,
)
def update_application(
    current_user: CurrentAdmin,
    application_id: int,
    payload: ApplicationUpdate,
    session: SessionDep,
) -> ApplicationResponse:

    service = ApplicationService(session)

    application = service.update(
        application_id=application_id,
        name=payload.name,
        description=payload.description,
        owner=payload.owner,
        criticality=payload.criticality,
    )

    return ApplicationResponse.model_validate(
        application,
    )


@router.delete(
    "/{application_id}",
    status_code=204,
)
def delete_application(
    current_user: CurrentAdmin,
    application_id: int,
    session: SessionDep,
) -> Response:

    service = ApplicationService(session)

    service.delete_by_id(
        application_id,
    )

    return Response(
        status_code=204,
    )
