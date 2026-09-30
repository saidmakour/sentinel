from fastapi import APIRouter
from fastapi import status

router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"],
)


@router.get(
    "/health",
    response_model=dict[str, str],
    status_code=status.HTTP_200_OK,
)
def health() -> dict[str, str]:
    return {
        "status": "ok",
    }
