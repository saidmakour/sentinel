class NoSourceAvailableError(ValueError):
    """No source available."""


class SourcePreparationError(ValueError):
    """Local source not found"""


class GitCloneError(Exception):
    pass


class GitPullError(Exception):
    pass


class GitCheckoutError(Exception):
    pass


class InvalidRepositoryError(ValueError):
    """Raised when a repository is invalid."""

    pass
