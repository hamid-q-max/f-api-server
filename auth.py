"""Authentication utilities for f-api-server."""

import base64
import hashlib
import hmac
import os
import secrets
import time

import jwt


ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_TTL_SECONDS = int(os.getenv("ACCESS_TOKEN_TTL_SECONDS", "3600"))


def get_jwt_secret_key() -> str:
    """Return the JWT secret key.

    Note: We intentionally avoid validating this at import-time so the service can
    start in dev/test environments where auth endpoints may not be exercised.
    """
    secret = os.getenv("JWT_SECRET_KEY")
    if not secret:
        raise RuntimeError("JWT_SECRET_KEY environment variable is required")
    return secret

# PBKDF2 parameters
_PBKDF2_ITERATIONS = int(os.getenv("PASSWORD_HASH_ITERATIONS", "200000"))


def hash_password(password: str) -> str:
    """Hash a password for storage using PBKDF2-HMAC-SHA256."""
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return "pbkdf2_sha256${}${}${}".format(
        _PBKDF2_ITERATIONS,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(dk).decode("ascii"),
    )


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its stored PBKDF2 hash."""
    try:
        scheme, iterations_s, salt_b64, dk_b64 = hashed_password.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        iterations = int(iterations_s)
        salt = base64.b64decode(salt_b64.encode("ascii"))
        expected = base64.b64decode(dk_b64.encode("ascii"))
    except Exception:
        return False

    computed = hashlib.pbkdf2_hmac(
        "sha256", plain_password.encode("utf-8"), salt, iterations
    )
    return hmac.compare_digest(computed, expected)


def create_access_token(user_id: int, role: str = "user") -> str:
    """Create a JWT access token with an expiration (exp) claim."""
    now = int(time.time())
    payload = {
        "user_id": user_id,
        "role": role,
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL_SECONDS,
    }
    return jwt.encode(payload, get_jwt_secret_key(), algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token.

    Raises jwt.InvalidTokenError on validation failures.
    """
    return jwt.decode(token, get_jwt_secret_key(), algorithms=[ALGORITHM])


def is_admin(token: str) -> bool:
    """Check if the token belongs to an admin user."""
    payload = decode_token(token)
    return payload.get("role") == "admin"
