from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError
from argon2.exceptions import VerificationError
from argon2.exceptions import VerifyMismatchError

_password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """
    Hash a password using Argon2id.
    """
    return _password_hasher.hash(password)


def verify_password(
    password: str,
    password_hash: str,
) -> bool:
    """
    Verify a password against an Argon2 hash.

    Returns False when the password does not match or
    when the stored hash cannot be verified.
    """
    try:
        return _password_hasher.verify(
            password_hash,
            password,
        )
    except (
        InvalidHashError,
        VerifyMismatchError,
        VerificationError,
    ):
        return False
