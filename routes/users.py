from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from models.user import UserResponse, UserCreate, UserUpdate
from auth import decode_token, hash_password
import logging
import sqlite3

router = APIRouter()
logger = logging.getLogger(__name__)

security = HTTPBearer(auto_error=False)


def _api_error(status_code: int, message: str, type_: str):
    return JSONResponse(
        status_code=status_code,
        content={"status": status_code, "message": message, "type": type_},
    )


def _get_auth_payload(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    """Return decoded JWT payload from an Authorization: Bearer token.

    Raises 401 if the token is missing or invalid.
    """
    if credentials is None or not credentials.credentials:
        return {"__error__": {"status": status.HTTP_401_UNAUTHORIZED, "message": "Missing bearer token", "type": "unauthorized"}}
    try:
        return decode_token(credentials.credentials)
    except Exception:
        return {"__error__": {"status": status.HTTP_401_UNAUTHORIZED, "message": "Invalid or expired token", "type": "unauthorized"}}


@router.get("/api/users/{user_id}", response_model=UserResponse)
async def get_user(user_id: int):
    """Fetch a single user by id."""
    conn = sqlite3.connect("users.db")
    cursor = conn.execute(
        "SELECT id, username, email, is_active, role FROM users WHERE id = ?",
        (user_id,),
    )
    row = cursor.fetchone()
    if row is None:
        return _api_error(status.HTTP_404_NOT_FOUND, "User not found", "not_found")

    user_id_db, username, email, is_active, role = row
    return UserResponse(
        user_id=user_id_db,
        user_name=username,
        username=username,
        email=email,
        is_active=bool(is_active),
        role=role or "user",
    )


@router.post("/api/users", response_model=UserResponse)
async def create_user(user: UserCreate):
    """Create a new user.

    Stores only a password hash in the database.
    """
    password_hash = hash_password(user.password)

    conn = sqlite3.connect("users.db")
    cursor = conn.execute(
        "INSERT INTO users (username, email, password_hash, is_active, role) VALUES (?, ?, ?, ?, ?)",
        (user.username, user.email, password_hash, 1, "user"),
    )
    conn.commit()

    user_id = cursor.lastrowid
    return UserResponse(user_id=user_id, user_name=user.username, username=user.username, email=user.email, is_active=True)


@router.put("/api/users/{user_id}")
async def update_user(user_id: int, update: UserUpdate, payload: dict = Depends(_get_auth_payload)):
    """Update a user's fields.

    Only admins may update other users or change roles.
    """
    if payload.get("__error__"):
        err = payload["__error__"]
        return _api_error(err["status"], err["message"], err["type"])

    requester_id = payload.get("user_id")
    requester_role = payload.get("role")

    if requester_role != "admin" and requester_id != user_id:
        return _api_error(status.HTTP_403_FORBIDDEN, "Forbidden", "forbidden")

    if update.role is not None and requester_role != "admin":
        return _api_error(status.HTTP_403_FORBIDDEN, "Only admins may change roles", "forbidden")

    fields = []
    params = []
    if update.username is not None:
        fields.append("username = ?")
        params.append(update.username)
    if update.email is not None:
        fields.append("email = ?")
        params.append(update.email)
    if update.role is not None:
        fields.append("role = ?")
        params.append(update.role)
    if update.is_active is not None:
        fields.append("is_active = ?")
        params.append(1 if update.is_active else 0)

    if not fields:
        return {"message": "No changes", "user_id": user_id}

    params.append(user_id)
    conn = sqlite3.connect("users.db")
    conn.execute(f"UPDATE users SET {', '.join(fields)} WHERE id = ?", tuple(params))
    conn.commit()

    return {"message": "User updated", "user_id": user_id}


@router.delete("/api/users/{user_id}")
async def delete_user(user_id: int, payload: dict = Depends(_get_auth_payload)):
    """Delete a user.

    Only admins may delete other users; users may delete their own account.
    """
    if payload.get("__error__"):
        err = payload["__error__"]
        return _api_error(err["status"], err["message"], err["type"])

    requester_id = payload.get("user_id")
    requester_role = payload.get("role")

    if requester_role != "admin" and requester_id != user_id:
        return _api_error(status.HTTP_403_FORBIDDEN, "Forbidden", "forbidden")

    conn = sqlite3.connect("users.db")
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    return {"message": f"User {user_id} deleted"}


@router.get("/api/admin/users")
async def list_all_users(payload: dict = Depends(_get_auth_payload)):
    """List all users (admin-only)."""
    if payload.get("__error__"):
        err = payload["__error__"]
        return _api_error(err["status"], err["message"], err["type"])

    if payload.get("role") != "admin":
        return _api_error(status.HTTP_403_FORBIDDEN, "Admin access required", "forbidden")

    conn = sqlite3.connect("users.db")
    cursor = conn.execute("SELECT id, username, email, is_active, role FROM users")
    rows = cursor.fetchall()
    users = [
        {
            "user_id": r[0],
            "user_name": r[1],
            "username": r[1],
            "email": r[2],
            "is_active": bool(r[3]),
            "role": r[4] or "user",
        }
        for r in rows
    ]
    return {"users": users}


@router.get("/api/users/search")
async def search_users(q: str):
    """Search users by username or email."""
    conn = sqlite3.connect("users.db")
    pattern = f"%{q}%"
    cursor = conn.execute(
        "SELECT id, username, email, is_active, role FROM users WHERE username LIKE ? OR email LIKE ?",
        (pattern, pattern),
    )
    rows = cursor.fetchall()
    results = [
        {
            "user_id": r[0],
            "user_name": r[1],
            "username": r[1],
            "email": r[2],
            "is_active": bool(r[3]),
            "role": r[4] or "user",
        }
        for r in rows
    ]
    return {"results": results}
