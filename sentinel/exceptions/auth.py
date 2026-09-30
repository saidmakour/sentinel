class UserAlreadyExistsError(Exception):
    """Username already exists."""


class UserNotFoundError(Exception):
    """User not found."""


class LastAdminError(Exception):
    """Operation would remove the last administrator."""
