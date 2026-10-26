"""
PadhanaAI Database Access Module
Decoupled database connection manager to prevent circular imports.
Supports serverless deployment environments (e.g., Vercel) where the filesystem is read-only except /tmp.
"""

import os
import sqlite3
import tempfile
from flask import g

# Support Vercel serverless environment (read-only filesystem, writable /tmp)
if os.getenv("VERCEL"):
    DATA_DIR = os.path.join(tempfile.gettempdir(), "padhanaai_data")
else:
    DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "app.db")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")
os.makedirs(BACKUP_DIR, exist_ok=True)

def get_db():
    """Returns the application-context database connection with foreign keys enabled."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

def close_db(e=None):
    """Closes the current database connection at the end of the request context."""
    d = g.pop("db", None)
    if d:
        d.close()

# Alias for backward compatibility
db = get_db
