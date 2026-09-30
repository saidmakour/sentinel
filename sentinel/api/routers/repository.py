from typing import Annotated

from fastapi import APIRouter
from fastapi import Depends
from sqlalchemy.orm import Session

from sentinel.api.dependencies import get_session
from sentinel.api.schemas.repository import RepositoryCreate
from sentinel.api.schemas.repository import RepositoryResponse
from sentinel.api.schemas.repository import RepositoryUpdate
from sentinel.security.dependencies import CurrentAdmin
from sentinel.security.dependencies import CurrentUser
from sentinel.services.repository_service import RepositoryService

router = APIRouter(
    prefix="/repositories",
    tags=["repositories"],
)

SessionDep = Annotated[
    Session,
    Depends(get_session),
]


@router.get(
    "",
    response_model=list[RepositoryResponse],
)
def list_repositories(
    current_user: CurrentUser,
    application_id: int,
    session: SessionDep,
) -> list[RepositoryResponse]:

    service = RepositoryService(session)

    repositories = service.list_by_application(
        application_id,
    )

    return [RepositoryResponse.model_validate(repo) for repo in repositories]


@router.get(
    "/{repository_id}",
    response_model=RepositoryResponse,
)
def get_repository(
    current_user: CurrentUser,
    repository_id: int,
    session: SessionDep,
) -> RepositoryResponse:

    service = RepositoryService(session)

    repository = service.get_by_id(
        repository_id,
    )

    return RepositoryResponse.model_validate(
        repository,
    )


@router.post(
    "",
    response_model=RepositoryResponse,
    status_code=201,
)
def create_repository(
    current_user: CurrentAdmin,
    payload: RepositoryCreate,
    session: SessionDep,
) -> RepositoryResponse:

    service = RepositoryService(session)

    repository = service.create(
        application_id=payload.application_id,
        name=payload.name,
        local_path=payload.local_path,
        remote_url=payload.remote_url or "",
        auth_method=payload.auth_method,
        default_branch=payload.default_branch,
        language=payload.language,
        package_manager=payload.package_manager,
    )

    return RepositoryResponse.model_validate(
        repository,
    )


@router.patch(
    "/{repository_id}",
    response_model=RepositoryResponse,
)
def update_repository(
    current_user: CurrentAdmin,
    repository_id: int,
    payload: RepositoryUpdate,
    session: SessionDep,
) -> RepositoryResponse:

    service = RepositoryService(session)

    repository = service.update(
        repository_id=repository_id,
        name=payload.name,
        local_path=payload.local_path,
        remote_url=payload.remote_url,
        auth_method=payload.auth_method,
        default_branch=payload.default_branch,
        language=payload.language,
        package_manager=payload.package_manager,
    )

    return RepositoryResponse.model_validate(
        repository,
    )


@router.delete(
    "/{repository_id}",
    status_code=204,
)
def delete_repository(
    current_user: CurrentAdmin,
    repository_id: int,
    session: SessionDep,
) -> None:

    service = RepositoryService(session)

    service.delete(
        repository_id,
    )
