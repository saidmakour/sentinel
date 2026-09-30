from sentinel.security.password import hash_password
from sentinel.security.password import verify_password


def test_hash_password_returns_hash() -> None:
    password = "SuperSecretPassword123!"

    password_hash = hash_password(password)

    assert password_hash != password
    assert password_hash.startswith("$argon2")


def test_hash_password_generates_different_hashes() -> None:
    password = "SuperSecretPassword123!"

    first_hash = hash_password(password)
    second_hash = hash_password(password)

    assert first_hash != second_hash


def test_verify_password_returns_true_for_valid_password() -> None:
    password = "SuperSecretPassword123!"

    password_hash = hash_password(password)

    assert verify_password(
        password,
        password_hash,
    )


def test_verify_password_returns_false_for_invalid_password() -> None:
    password = "SuperSecretPassword123!"

    password_hash = hash_password(password)

    assert not verify_password(
        "WrongPassword123!",
        password_hash,
    )


def test_verify_password_returns_false_for_invalid_hash() -> None:
    assert not verify_password(
        "SuperSecretPassword123!",
        "invalid-hash",
    )
