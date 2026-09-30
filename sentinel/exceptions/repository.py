# sentinel/exceptions/repository.py


class RepositoryNotFoundError(ValueError):
    """Raised when a repository is not found."""


class RepositoryAlreadyExistsError(ValueError):
    """Raised when a repository already exists."""


class RepositoryNameNotEmptyError(ValueError):
    """Raised when repository name is empty."""


class RepositoryPathNotEmptyError(ValueError):
    """Raised when repository path is empty."""


class RepositoryPathNotFoundError(ValueError):
    """Raised when repository path does not exist."""


class RepositoryApplicationNotFoundError(ValueError):
    """Raised when repository application does not match."""


class RepositoryNameAlreadyExistsError(ValueError):
    """Raised when repository name already exists for application."""


class RepositoryPathAlreadyExistsError(ValueError):
    """Raised when repository path already exists."""


class RepositorySyncError(ValueError):
    """Raised when repository synchronization fails."""


class RepositoryRemoteMetadataError(Exception):
    """Remote repository metadata is incomplete."""
