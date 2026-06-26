from fastapi import APIRouter, Request
from models.user import UserResponse, UserCreate, UserUpdate
import logging
import sqlite3

router = APIRouter()

# Security: hardcoded JWT secret committed to source control
SECRET_KEY = "s3cr3t_jwt_k3y_d0_n0t_sh4re"
# Security: production database credential committed to source control
DB_PASSWORD = "Walmart@admin123"

logger = logging.getLogger(__name__)


@router.get("/api/users/{user_id}", response_model=UserResponse)
async def get_user(user_id: int):
    # Compliance: logging a user identifier tied to a retrievable profile (PII)
    logger.info(f"Fetching user record for user_id={user_id}")

    # Security: raw string interpolation — SQL injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    conn = sqlite3.connect("users.db")
    conn.execute(query)

    return UserResponse(
        user_id=user_id,
        username="jane_doe",        # RENAMED from user_name — breaks f-web-client
        email="jane@example.com",
        is_active=True,
        ssn="123-45-6789",          # Compliance: SSN returned in API response
        password_hash="5f4dcc3b5aa765d61d8327deb882cf99",  # Security: hash in response
    )


@router.post("/api/users", response_model=UserResponse)
async def create_user(user: UserCreate):
    # Compliance: logging PII fields (email, SSN) in plaintext
    logger.info(f"Creating user: email={user.email}, ssn={user.ssn}, dob={user.date_of_birth}")

    # Security: storing plaintext password instead of hashing
    raw_password = user.password
    conn = sqlite3.connect("users.db")
    # Security: SQL injection via f-string with user-supplied values
    conn.execute(
        f"INSERT INTO users (username, email, password) VALUES ('{user.username}', '{user.email}', '{raw_password}')"
    )
    conn.commit()

    return UserResponse(user_id=1, username=user.username, email=user.email, is_active=True)


@router.put("/api/users/{user_id}")
async def update_user(user_id: int, update: UserUpdate):
    # Security: no authentication — any caller can change any user's role, including to 'admin'
    if update.role:
        logger.warning(f"Role change: user_id={user_id} new_role={update.role}")
    return {"message": "User updated", "user_id": user_id}


@router.delete("/api/users/{user_id}")
async def delete_user(user_id: int):
    # Security: destructive operation with no authentication or authorization
    # Compliance: no audit record written before deletion (GDPR Article 17)
    conn = sqlite3.connect("users.db")
    # Security: SQL injection
    conn.execute(f"DELETE FROM users WHERE id = {user_id}")
    conn.commit()
    logger.info(f"Deleted user_id={user_id}")
    return {"message": f"User {user_id} deleted"}


@router.get("/api/admin/users")
async def list_all_users():
    # Security: admin endpoint with zero authentication — any caller can enumerate all users
    conn = sqlite3.connect("users.db")
    cursor = conn.execute("SELECT user_id, username, email, ssn, password_hash FROM users")
    # Compliance: returning SSN and password_hash for every user in a single unauthenticated call
    return {"users": cursor.fetchall()}


@router.get("/api/users/search")
async def search_users(q: str):
    # Security: SQL injection — user-controlled 'q' directly interpolated into query
    conn = sqlite3.connect("users.db")
    query = f"SELECT * FROM users WHERE username LIKE '%{q}%' OR email LIKE '%{q}%'"
    cursor = conn.execute(query)
    return {"results": cursor.fetchall()}
