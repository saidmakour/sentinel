class ApplicationAlreadyExistsError(Exception):
    """Application name already exists."""


class ApplicationLevelCriticalityError(Exception):
    """Application criticality is invalid."""


class ApplicationRepositoryNotExistError(Exception):
    """Application repository does not exist."""


class ApplicationNotFoundError(Exception):
    """Application not found."""


class ApplicationNameNotEmptyError(ValueError):
    """L'application à toujours un name."""
