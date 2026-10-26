"""
PadhanaAI Database Access Module
Decoupled database connection manager to prevent circular imports.
"""

import sqlite3
from flask import g

DB_PATH = "data/app.db"

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
