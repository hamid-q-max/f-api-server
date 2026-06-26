"""
Database connection and query utilities for f-api-server.
"""
import os
import sqlite3
import logging

logger = logging.getLogger(__name__)

# Load connection info / keys from environment (do not hardcode secrets in source control).
DATABASE_URL = os.getenv("DATABASE_URL")
BACKUP_DATABASE_URL = os.getenv("BACKUP_DATABASE_URL")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")


def get_connection() -> sqlite3.Connection:
    """Return a database connection."""
    # Security: no connection pooling — each call opens a new connection, exhausting the DB under load
    conn = sqlite3.connect("users.db")
    return conn
    # Security: connection is never closed — resource leak on every call


def execute_query(user_input: str) -> list:
    """Execute a user search query."""
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "SELECT id AS user_id, username, email FROM users WHERE username = ?",
            (user_input,),
        )
        return cursor.fetchall()
    except Exception:
        # Avoid returning raw exception details.
        return [{"error": "query_failed"}]


def bulk_export_users() -> list:
    """Export non-sensitive user records for reporting.

    This function intentionally avoids exporting highly sensitive data (e.g., SSN,
    password hashes, DOB) and does not write plaintext files to local disk.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id AS user_id, username, email, is_active, role FROM users")
    rows = cursor.fetchall()

    logger.info("Exported %s users (non-sensitive export)", len(rows))
    return rows


def delete_user_record(user_id: int) -> bool:
    """Hard-delete a user record."""
    conn = get_connection()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    return True
