from fastapi import FastAPI
from fastapi import Request
from fastapi.responses import JSONResponse

from sentinel.exceptions.application import ApplicationAlreadyExistsError
from sentinel.exceptions.application import ApplicationLevelCriticalityError
from sentinel.exceptions.application import ApplicationNameNotEmptyError
from sentinel.exceptions.application import ApplicationNotFoundError
from sentinel.exceptions.application import ApplicationRepositoryNotExistError
from sentinel.exceptions.renderer import RendererNotFoundError
from sentinel.exceptions.repository import RepositoryApplicationNotFoundError
from sentinel.exceptions.repository import RepositoryNameAlreadyExistsError
from sentinel.exceptions.repository import RepositoryNameNotEmptyError
from sentinel.exceptions.repository import RepositoryNotFoundError
from sentinel.exceptions.repository import RepositoryPathAlreadyExistsError
from sentinel.exceptions.repository import RepositoryPathNotEmptyError
from sentinel.exceptions.repository import RepositoryPathNotFoundError
from sentinel.exceptions.repository import RepositoryRemoteMetadataError
from sentinel.exceptions.scan import ScanNotFoundError


async def renderer_not_found_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:

    return JSONResponse(
        status_code=400,
        content={
            "detail": str(exc),
        },
    )


async def application_not_found_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:

    return JSONResponse(
        status_code=404,
        content={"detail": str(exc)},
    )


async def application_already_exists_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:

    return JSONResponse(
        status_code=409,
        content={"detail": str(exc)},
    )


async def application_level_criticality_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:

    return JSONResponse(
        status_code=400,
        content={"detail": str(exc)},
    )


async def application_repository_not_exist_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:

    return JSONResponse(
        status_code=404,
        content={"detail": str(exc)},
    )


async def repository_application_not_found_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    return JSONResponse(
        status_code=404,
        content={"detail": str(exc)},
    )


async def repository_name_exists_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    return JSONResponse(
        status_code=409,
        content={"detail": str(exc)},
    )


async def repository_path_exists_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    return JSONResponse(
        status_code=409,
        content={"detail": str(exc)},
    )


async def repository_name_empty_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content={"detail": str(exc)},
    )


async def repository_path_empty_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content={"detail": str(exc)},
    )


async def repository_path_not_found_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content={"detail": str(exc)},
    )


async def repository_not_found_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    return JSONResponse(
        status_code=404,
        content={"detail": str(exc)},
    )


async def scan_not_found_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:

    return JSONResponse(
        status_code=404,
        content={"detail": str(exc)},
    )


async def repository_remote_metadata_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content={"detail": str(exc)},
    )


async def application_name_not_empty_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:

    return JSONResponse(
        status_code=400,
        content={"detail": str(exc)},
    )


def register_exception_handlers(
    app: FastAPI,
) -> None:

    app.add_exception_handler(
        ApplicationNotFoundError,
        application_not_found_handler,
    )
    app.add_exception_handler(
        ApplicationRepositoryNotExistError,
        application_repository_not_exist_handler,
    )

    app.add_exception_handler(
        ApplicationAlreadyExistsError,
        application_already_exists_handler,
    )

    app.add_exception_handler(
        ApplicationLevelCriticalityError,
        application_level_criticality_handler,
    )

    app.add_exception_handler(
        RepositoryApplicationNotFoundError,
        repository_application_not_found_handler,
    )

    app.add_exception_handler(
        RepositoryNameAlreadyExistsError,
        repository_name_exists_handler,
    )

    app.add_exception_handler(
        RepositoryPathAlreadyExistsError,
        repository_path_exists_handler,
    )

    app.add_exception_handler(
        RepositoryNameNotEmptyError,
        repository_name_empty_handler,
    )

    app.add_exception_handler(
        RepositoryPathNotEmptyError,
        repository_path_empty_handler,
    )

    app.add_exception_handler(
        RepositoryPathNotFoundError,
        repository_path_not_found_handler,
    )

    app.add_exception_handler(
        RepositoryNotFoundError, repository_not_found_handler
    )

    app.add_exception_handler(
        ScanNotFoundError,
        scan_not_found_handler,
    )

    app.add_exception_handler(
        RendererNotFoundError,
        renderer_not_found_handler,
    )

    app.add_exception_handler(
        RepositoryRemoteMetadataError,
        repository_remote_metadata_handler,
    )

    app.add_exception_handler(
        ApplicationNameNotEmptyError,
        application_name_not_empty_handler,
    )
