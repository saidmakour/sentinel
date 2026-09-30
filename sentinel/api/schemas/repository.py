from pydantic import BaseModel

from sentinel.enums.git_auth_method import GitAuthMethod


class RepositoryCreate(BaseModel):
    application_id: int
    name: str
    local_path: str
    remote_url: str | None = None
    auth_method: GitAuthMethod = GitAuthMethod.NONE
    default_branch: str = "main"
    language: str = "python"
    package_manager: str = "pip"


class RepositoryUpdate(BaseModel):
    name: str | None = None
    local_path: str | None = None
    remote_url: str | None = None
    auth_method: GitAuthMethod | None = None
    default_branch: str | None = None
    language: str | None = None
    package_manager: str | None = None


class RepositoryResponse(BaseModel):
    id: int
    application_id: int
    name: str
    local_path: str
    remote_url: str
    auth_method: GitAuthMethod
    default_branch: str
    language: str
    package_manager: str
    enabled: bool

    model_config = {
        "from_attributes": True,
    }
