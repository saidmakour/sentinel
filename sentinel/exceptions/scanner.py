# sentinel/exceptions/scanner.py


class InvalidFileError(ValueError):
    """Raised when invalide file"""


class InvalidManifestError(ValueError):
    """Raised when a dependency manifest is invalid."""


class UnsupportedLanguageError(ValueError):
    """Raised when language not exist"""
