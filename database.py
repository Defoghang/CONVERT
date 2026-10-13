import sqlite3
from contextlib import contextmanager
from config import DATABASE_PATH


def init_db():
    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                username TEXT,
                first_name TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS stats (
                key TEXT PRIMARY KEY,
                value INTEGER DEFAULT 0
            )
        """)
        conn.execute("INSERT OR IGNORE INTO stats (key, value) VALUES ('messages_processed', 0)")
        conn.commit()


@contextmanager
def get_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def upsert_user(user_id, username, first_name):
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO users (user_id, username, first_name, last_seen)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) DO UPDATE SET
                username = excluded.username,
                first_name = excluded.first_name,
                last_seen = CURRENT_TIMESTAMP
        """, (user_id, username, first_name))


def get_user(user_id):
    with get_connection() as conn:
        cur = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
        return cur.fetchone()


def increment_stat(key):
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO stats (key, value) VALUES (?, 1)
            ON CONFLICT(key) DO UPDATE SET value = value + 1
        """, (key,))


def get_stat(key):
    with get_connection() as conn:
        cur = conn.execute("SELECT value FROM stats WHERE key = ?", (key,))
        row = cur.fetchone()
        return row["value"] if row else 0
