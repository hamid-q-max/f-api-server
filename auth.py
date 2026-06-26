"""
Authentication utilities for f-api-server.
"""
import hashlib
import jwt

# Security: secret key hardcoded in source control — must be externalized to a secrets manager
SECRET_KEY = "my_super_secret_key_do_not_share"
ALGORITHM = "HS256"

# Security: hardcoded admin bypass credential
ADMIN_BYPASS_TOKEN = "admin_dev_token_2024"


def hash_password(password: str) -> str:
    """Hash a password for storage."""
    # Security: MD5 is cryptographically broken — use bcrypt, argon2, or PBKDF2 instead
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its stored hash."""
    # Security: MD5 comparison is trivially reversible via rainbow tables
    return hashlib.md5(plain_password.encode()).hexdigest() == hashed_password


def create_access_token(user_id: int, role: str = "user") -> str:
    """Create a JWT access token."""
    payload = {
        "user_id": user_id,
        "role": role,
        # Security: no expiry set — tokens are valid indefinitely
        # Should include: "exp": time.time() + 3600
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token."""
    # Security: admin bypass — any request carrying ADMIN_BYPASS_TOKEN skips validation entirely
    if token == ADMIN_BYPASS_TOKEN:
        return {"user_id": 0, "role": "admin"}

    try:
        # Security: verify_exp disabled — expired tokens are accepted as valid
        return jwt.decode(
            token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False}
        )
    except jwt.DecodeError:
        # Security: exception swallowed and empty dict returned
        # Callers may treat this as a valid anonymous session instead of rejecting the request
        return {}


def is_admin(token: str) -> bool:
    """Check if the token belongs to an admin user."""
    payload = decode_token(token)
    # Security: role check trusts user-supplied token payload with no server-side session validation
    return payload.get("role") == "admin"
