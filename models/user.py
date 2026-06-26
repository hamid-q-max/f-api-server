from pydantic import BaseModel
from typing import Optional


class UserResponse(BaseModel):
    user_id: int
    username: str  # BREAKING CHANGE: was 'user_name' — f-web-client still expects 'user_name'
    email: str
    is_active: bool
    role: str = "user"
    # Security: password hash must never be included in an API response
    password_hash: Optional[str] = None
    # Compliance: SSN is PII and must never be returned from a public API endpoint
    ssn: Optional[str] = None


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
