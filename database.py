"""Database engine and session configuration."""

import os
from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from models import Base


ROOT = Path(__file__).resolve().parent
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{ROOT / 'app.db'}")
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db() -> None:
    if "users" in inspect(engine).get_table_names():
        migrate_user_schema()
    Base.metadata.create_all(bind=engine)
    if "bank_accounts" in inspect(engine).get_table_names():
        columns = {
            column["name"] for column in inspect(engine).get_columns("bank_accounts")
        }
        if "qr_code_url" not in columns:
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "ALTER TABLE bank_accounts "
                        "ADD COLUMN qr_code_url VARCHAR(1000) NOT NULL DEFAULT ''"
                    )
                )


def migrate_user_schema() -> None:
    """Add new account fields without dropping existing SQLite user data."""
    inspector = inspect(engine)
    columns = {column["name"] for column in inspector.get_columns("users")}
    new_columns = {
        "username": "VARCHAR(30)",
        "phone": "VARCHAR(40) NOT NULL DEFAULT ''",
        "address": "TEXT NOT NULL DEFAULT ''",
        "bank_account_number": "VARCHAR(100) NOT NULL DEFAULT ''",
        "secondary_password_hash": "VARCHAR(255)",
        "security_question": "VARCHAR(255) NOT NULL DEFAULT ''",
        "security_answer_hash": "VARCHAR(255)",
        "balance": "NUMERIC(14, 2) NOT NULL DEFAULT 0",
        "account_status": "VARCHAR(20) NOT NULL DEFAULT 'active'",
        "trial_expires_at": "DATETIME",
        "created_at": "DATETIME",
    }
    with engine.begin() as connection:
        for name, sql_type in new_columns.items():
            if name not in columns:
                connection.execute(text(f"ALTER TABLE users ADD COLUMN {name} {sql_type}"))

        connection.execute(
            text("UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")
        )
        rows = connection.execute(
            text("SELECT id, email, username FROM users ORDER BY id")
        ).mappings()
        used_usernames = {
            row["username"].lower()
            for row in rows
            if row["username"]
        }
        missing_usernames = connection.execute(
            text(
                "SELECT id, email FROM users "
                "WHERE username IS NULL OR username = '' ORDER BY id"
            )
        ).mappings()
        for row in missing_usernames:
            base = "".join(
                char
                for char in row["email"].split("@", 1)[0].lower()
                if char.isascii() and (char.isalnum() or char in "_.-")
            )[:24]
            if len(base) < 3:
                base = f"user{row['id']}"
            candidate = base
            suffix = 1
            while candidate in used_usernames:
                tail = str(suffix)
                candidate = f"{base[:30 - len(tail)]}{tail}"
                suffix += 1
            used_usernames.add(candidate)
            connection.execute(
                text("UPDATE users SET username = :username WHERE id = :user_id"),
                {"username": candidate, "user_id": row["id"]},
            )

        connection.execute(
            text("CREATE UNIQUE INDEX IF NOT EXISTS ix_users_username ON users (username)")
        )
