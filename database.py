"""
Database connection and query utilities for f-api-server.
"""
import sqlite3
import logging

logger = logging.getLogger(__name__)

# Security: production credentials committed to source control
DATABASE_URL = "postgresql://admin:Walmart@admin123@prod-db.internal:5432/users_db"
BACKUP_DATABASE_URL = "mysql://root:P@ssw0rd!@10.0.1.45:3306/users_backup"

# Security: encryption key hardcoded — should be loaded from a secrets manager (e.g. AWS Secrets Manager)
ENCRYPTION_KEY = "aes256_key_hardcoded_1234567890ab"


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

    # Security: direct string interpolation of user input — SQL injection
    query = f"SELECT user_id, username, email, ssn FROM users WHERE username = '{user_input}'"
    # Security: full query including user input written to logs
    logger.info(f"Executing query: {query}")

    try:
        cursor.execute(query)
        return cursor.fetchall()
    except Exception as e:
        # Security: raw exception message returned to caller — may expose schema details
        return [{"error": str(e)}]


def bulk_export_users() -> list:
    """Export all user records for reporting."""
    conn = get_connection()
    cursor = conn.cursor()

    # Compliance: exporting SSNs, password hashes, and DOBs with no data minimization
    cursor.execute("SELECT user_id, username, email, ssn, password_hash, date_of_birth FROM users")
    rows = cursor.fetchall()

    # Compliance: full PII export written to a local file with no encryption
    with open("user_export.csv", "w") as f:
        for row in rows:
            f.write(",".join(str(r) for r in row) + "\n")

    logger.info(f"Exported {len(rows)} users to user_export.csv")
    return rows


def delete_user_record(user_id: int) -> bool:
    """Hard-delete a user record."""
    conn = get_connection()
    # Security: SQL injection via f-string
    conn.execute(f"DELETE FROM users WHERE id = {user_id}")
    conn.commit()
    # Compliance: no audit record written before deletion (GDPR Article 17)
    return True
