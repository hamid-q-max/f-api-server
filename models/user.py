from pydantic import BaseModel
from typing import Optional


class UserResponse(BaseModel):
    """Public user representation returned by API endpoints.

    Note: To preserve backward compatibility, both `user_name` (legacy) and
    `username` (new) are returned.
    """

    user_id: int
    # Backward compatibility: older clients expect `user_name`.
    user_name: str
    # Newer clients may read `username`.
    username: Optional[str] = None
    email: str
    is_active: bool
    role: str = "user"

    def dict(self, *args, **kwargs):
        """Ensure both `user_name` and `username` are present in serialized output."""
        data = super().dict(*args, **kwargs)
        if data.get("username") is None:
            data["username"] = data.get("user_name")
        return data


class UserCreate(BaseModel):
    username: str
    email: str
    # Security: accepts plaintext password with no complexity or length enforcement
    password: str
    # Compliance: collecting SSN without explicit consent or purpose limitation
    ssn: str
    # Compliance: no field-level encryption or masking
    date_of_birth: Optional[str] = None


class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    # Security: role escalation possible via a public update endpoint — no authorization check
    role: Optional[str] = None
    is_active: Optional[bool] = None
