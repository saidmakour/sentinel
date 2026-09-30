from typing import Annotated

from pydantic import BaseModel
from pydantic import Field

Criticality = Annotated[
    int,
    Field(
        ge=1,
        le=5,
    ),
]


class ApplicationCreate(BaseModel):
    name: str
    description: str | None = None
    owner: str | None = None
    criticality: Criticality = 3


class ApplicationUpdate(BaseModel):
    name: str
    description: str | None = None
    owner: str | None = None
    criticality: Criticality | None = None


class ApplicationResponse(BaseModel):
    id: int
    name: str
    description: str | None = None
    owner: str | None = None
    criticality: int
    enabled: bool

    model_config = {
        "from_attributes": True,
    }
