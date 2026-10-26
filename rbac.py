"""
PadhanaAI Enterprise RBAC & Security Engine
Centralized Permission System, Authorization Matrix & Database Policies
"""

import os
import json
import time
import sqlite3
from functools import wraps
from flask import g, session, request, redirect, url_for, abort, jsonify, flash, render_template

# ==============================================================================
# Role Definitions & Centralized Permission Matrix
# ==============================================================================

ROLES = {
    "super_admin": {
        "name": "Super Admin",
        "description": "Full unconstrained access to all platform, institution, and security modules.",
        "level": 100,
    },
    "institution_admin": {
        "name": "Institution Admin",
        "description": "Administrative authority over their institution, classrooms, teachers, and students.",
        "level": 80,
    },
    "teacher": {
        "name": "Teacher",
        "description": "Manages assigned classrooms, invites students, and shares academic reading materials.",
        "level": 50,
    },
    "student": {
        "name": "Student",
        "description": "Standard learner account with access to personal library and enrolled classrooms.",
        "level": 10,
    },
    "moderator_support": {
        "name": "Moderator / Support",
        "description": "Reviews reported content, moderates documents, and manages user support tickets.",
        "level": 60,
    },
}

# Fine-grained platform permissions grouped by module
PERMISSIONS = {
    # Users & Roles Module
    "users.view": "View user profiles and account statuses",
    "users.manage": "Update user profile details and status",
    "users.role_assign": "Assign or update roles for users",
    "users.deactivate": "Deactivate or reactivate user accounts",

    # Platform Analytics Module
    "analytics.view": "View global platform usage metrics and analytics",
    "analytics.institution": "View institution-scoped analytics and learning trends",

    # AI Usage & Costs Module
    "ai_usage.view": "Inspect token consumption, latency, and estimated cloud costs",
    "ai_config.manage": "Configure permitted AI models, prompts, quotas, and limits",

    # Content Moderation Module
    "moderation.view": "View reported documents and moderation queues",
    "moderation.action": "Take down, restore, or dismiss reported documents",

    # Security & Audit Logs Module
    "audit.view": "Inspect security events, login attempts, and permission audits",
    "audit.export": "Export audit records and security snapshots",

    # Feature Flags & Maintenance Module
    "features.manage": "Toggle platform feature flags and activate maintenance mode",

    # Support & Feedback Module
    "support.view": "View support inquiries and user feedback tickets",
    "support.manage": "Assign, update, and resolve support tickets",
    "support.create": "Create a support ticket or submit feedback",

    # Backup & Retention Module
    "backups.view": "View backup snapshots, retention schedules, and export logs",
    "backups.manage": "Trigger manual backups and process data erasure requests",

    # Institution & Classroom Management Module
    "institutions.view": "View institution profiles and directory",
    "institutions.manage": "Create, modify, and configure institutions",
    "classrooms.view": "View classrooms and student rosters",
    "classrooms.manage": "Create and configure classrooms",
    "classrooms.teach": "Manage classroom assignments and share study materials",

    # Document & RAG Core
    "documents.read_own": "Read own documents and study notes",
    "documents.upload": "Upload and index new study documents",
    "documents.share_classroom": "Share indexed documents with assigned classrooms",
}

# The Centralized Permission Matrix
ROLE_PERMISSIONS = {
    "super_admin": list(PERMISSIONS.keys()),  # Super admin holds all permissions

    "institution_admin": [
        "users.view",
        "users.manage",
        "users.role_assign",
        "users.deactivate",
        "analytics.institution",
        "moderation.view",
        "moderation.action",
        "support.view",
        "support.manage",
        "support.create",
        "institutions.view",
        "classrooms.view",
        "classrooms.manage",
        "classrooms.teach",
        "documents.read_own",
        "documents.upload",
        "documents.share_classroom",
    ],

    "teacher": [
        "classrooms.view",
        "classrooms.teach",
        "analytics.institution",
        "support.create",
        "documents.read_own",
        "documents.upload",
        "documents.share_classroom",
    ],

    "student": [
        "classrooms.view",
        "support.create",
        "documents.read_own",
        "documents.upload",
    ],

    "moderator_support": [
        "users.view",
        "moderation.view",
        "moderation.action",
        "support.view",
        "support.manage",
        "support.create",
        "audit.view",
        "documents.read_own",
        "documents.upload",
    ],
}

# ==============================================================================
# Database Schema Expansion for RBAC & Enterprise Modules
# ==============================================================================

RBAC_SCHEMA = """
-- User Profiles (extends the base users table)
CREATE TABLE IF NOT EXISTS profiles (
    user_id INTEGER PRIMARY KEY,
    full_name TEXT,
    avatar_url TEXT,
    institution_id INTEGER,
    status TEXT DEFAULT 'active' CHECK(status IN ('active', 'deactivated', 'suspended')),
    created_at REAL,
    updated_at REAL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(institution_id) REFERENCES institutions(id) ON DELETE SET NULL
);

-- Roles table
CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    is_system INTEGER DEFAULT 1
);

-- Permissions table
CREATE TABLE IF NOT EXISTS permissions (
    id INTEGER PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT
);

-- Role-Permissions junction table
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    PRIMARY KEY(role_id, permission_id),
    FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY(permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);

-- User-Roles junction table (Central authority for authorization)
CREATE TABLE IF NOT EXISTS user_roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    institution_id INTEGER,
    assigned_by INTEGER,
    created_at REAL,
    UNIQUE(user_id, role_id, institution_id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY(institution_id) REFERENCES institutions(id) ON DELETE CASCADE,
    FOREIGN KEY(assigned_by) REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS ix_user_roles_user ON user_roles(user_id);

-- Institutions table
CREATE TABLE IF NOT EXISTS institutions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    domain TEXT,
    status TEXT DEFAULT 'active' CHECK(status IN ('active', 'inactive')),
    created_at REAL
);

-- Classrooms table
CREATE TABLE IF NOT EXISTS classrooms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    institution_id INTEGER,
    name TEXT NOT NULL,
    code TEXT UNIQUE NOT NULL,
    teacher_id INTEGER NOT NULL,
    created_at REAL,
    FOREIGN KEY(institution_id) REFERENCES institutions(id) ON DELETE CASCADE,
    FOREIGN KEY(teacher_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_classrooms_inst ON classrooms(institution_id);

-- Classroom Members (Teacher and student enrollments)
CREATE TABLE IF NOT EXISTS classroom_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    classroom_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    role TEXT DEFAULT 'student' CHECK(role IN ('teacher', 'student')),
    joined_at REAL,
    UNIQUE(classroom_id, user_id),
    FOREIGN KEY(classroom_id) REFERENCES classrooms(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_classroom_members_user ON classroom_members(user_id);

-- Shared Documents in Classrooms
CREATE TABLE IF NOT EXISTS shared_documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    doc_id INTEGER NOT NULL,
    classroom_id INTEGER NOT NULL,
    shared_by INTEGER NOT NULL,
    created_at REAL,
    UNIQUE(doc_id, classroom_id),
    FOREIGN KEY(doc_id) REFERENCES docs(id) ON DELETE CASCADE,
    FOREIGN KEY(classroom_id) REFERENCES classrooms(id) ON DELETE CASCADE,
    FOREIGN KEY(shared_by) REFERENCES users(id) ON DELETE CASCADE
);

-- Security and Audit Logs (append-only table)
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    ip_address TEXT,
    user_agent TEXT,
    details TEXT,
    status TEXT DEFAULT 'success',
    created_at REAL
);
CREATE INDEX IF NOT EXISTS ix_audit_logs_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS ix_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS ix_audit_logs_created ON audit_logs(created_at);

-- Feature Flags & Maintenance Mode
CREATE TABLE IF NOT EXISTS feature_flags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    is_enabled INTEGER DEFAULT 1,
    audience TEXT DEFAULT 'all' CHECK(audience IN ('all', 'institution', 'beta', 'admin_only')),
    updated_at REAL
);

-- AI Model Configuration
CREATE TABLE IF NOT EXISTS ai_model_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tier TEXT UNIQUE NOT NULL,
    model_id TEXT NOT NULL,
    max_tokens INTEGER DEFAULT 1200,
    temperature REAL DEFAULT 0.2,
    system_prompt TEXT,
    is_active INTEGER DEFAULT 1,
    updated_at REAL
);

-- AI Usage and Cost Events
CREATE TABLE IF NOT EXISTS ai_usage_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    doc_id INTEGER,
    kind TEXT NOT NULL,
    model TEXT,
    prompt_tokens INTEGER DEFAULT 0,
    completion_tokens INTEGER DEFAULT 0,
    latency_ms REAL DEFAULT 0,
    cost_est REAL DEFAULT 0.0,
    error TEXT,
    created_at REAL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_ai_usage_user ON ai_usage_events(user_id);
CREATE INDEX IF NOT EXISTS ix_ai_usage_created ON ai_usage_events(created_at);

-- Support and Feedback Tickets
CREATE TABLE IF NOT EXISTS support_tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    institution_id INTEGER,
    subject TEXT NOT NULL,
    description TEXT NOT NULL,
    priority TEXT DEFAULT 'medium' CHECK(priority IN ('low', 'medium', 'high', 'urgent')),
    status TEXT DEFAULT 'open' CHECK(status IN ('open', 'in_progress', 'resolved', 'closed')),
    assigned_to INTEGER,
    feedback_rating INTEGER,
    created_at REAL,
    updated_at REAL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(assigned_to) REFERENCES users(id) ON DELETE SET NULL
);

-- Document Moderation Reports
CREATE TABLE IF NOT EXISTS document_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    doc_id INTEGER NOT NULL,
    reporter_id INTEGER NOT NULL,
    reason TEXT NOT NULL,
    status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'reviewed', 'dismissed', 'takedown')),
    notes TEXT,
    resolved_by INTEGER,
    created_at REAL,
    updated_at REAL,
    FOREIGN KEY(doc_id) REFERENCES docs(id) ON DELETE CASCADE,
    FOREIGN KEY(reporter_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(resolved_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Backup Snapshots metadata
CREATE TABLE IF NOT EXISTS backup_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    size_bytes INTEGER,
    status TEXT DEFAULT 'completed',
    retention_days INTEGER DEFAULT 90,
    created_at REAL
);
"""

# ==============================================================================
# Schema Initialization & Development Seeding
# ==============================================================================

def init_rbac_db(db_conn):
    """Executes the RBAC database schema and seeds initial roles and permissions."""
    db_conn.row_factory = sqlite3.Row
    db_conn.executescript(RBAC_SCHEMA)

    # 1. Seed Roles
    for slug, meta in ROLES.items():
        db_conn.execute(
            "INSERT OR IGNORE INTO roles(slug, name, description) VALUES(?, ?, ?)",
            (slug, meta["name"], meta["description"])
        )

    # 2. Seed Permissions
    for slug, desc in PERMISSIONS.items():
        db_conn.execute(
            "INSERT OR IGNORE INTO permissions(slug, name, description) VALUES(?, ?, ?)",
            (slug, slug.replace(".", " ").title(), desc)
        )

    # 3. Seed Role-Permissions mappings
    role_rows = {r["slug"]: r["id"] for r in db_conn.execute("SELECT id, slug FROM roles").fetchall()}
    perm_rows = {p["slug"]: p["id"] for p in db_conn.execute("SELECT id, slug FROM permissions").fetchall()}

    for role_slug, perms in ROLE_PERMISSIONS.items():
        role_id = role_rows.get(role_slug)
        if not role_id:
            continue
        for p_slug in perms:
            perm_id = perm_rows.get(p_slug)
            if perm_id:
                db_conn.execute(
                    "INSERT OR IGNORE INTO role_permissions(role_id, permission_id) VALUES(?, ?)",
                    (role_id, perm_id)
                )

    # 4. Seed Default Feature Flags
    default_flags = [
        ("maintenance_mode", "Maintenance Mode", "When enabled, non-admin access is temporarily restricted", 0, "admin_only"),
        ("ai_chat", "Grounded AI Chat", "Permits vector-grounded dialogue with uploaded documents", 1, "all"),
        ("smart_summaries", "Executive Synthesis", "Enables 5-sentence briefs and deep dive study summaries", 1, "all"),
        ("active_recall_quizzes", "Interactive Quizzes", "Dynamic multiple-choice knowledge assessments", 1, "all"),
        ("classroom_sharing", "Classroom Document Sharing", "Permits educators to share materials with student rosters", 1, "institution"),
        ("strict_rate_limiting", "Strict Rate Limiting", "Enforces lower request thresholds during peak hours", 0, "all"),
    ]
    for key, name, desc, enabled, audience in default_flags:
        db_conn.execute(
            "INSERT OR IGNORE INTO feature_flags(key, name, description, is_enabled, audience, updated_at) VALUES(?, ?, ?, ?, ?, ?)",
            (key, name, desc, enabled, audience, time.time())
        )

    # 5. Seed Default AI Model Configurations
    default_models = [
        ("simple", "meta-llama/Meta-Llama-3.1-8B-Instruct", 900, 0.2, "Answer strictly from context.", 1),
        ("standard", "meta-llama/Meta-Llama-3.1-70B-Instruct", 1500, 0.2, "Provide detailed grounded answers with page citations.", 1),
        ("complex", "meta-llama/Meta-Llama-3.1-405B-Instruct", 2000, 0.2, "In-depth multi-step academic reasoning.", 1),
    ]
    for tier, model_id, max_tok, temp, sys_p, active in default_models:
        db_conn.execute(
            "INSERT OR IGNORE INTO ai_model_configs(tier, model_id, max_tokens, temperature, system_prompt, is_active, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?)",
            (tier, model_id, max_tok, temp, sys_p, active, time.time())
        )

    # 6. Ensure default profiles for any existing users
    db_conn.execute("""
        INSERT OR IGNORE INTO profiles(user_id, full_name, status, created_at, updated_at)
        SELECT id, SUBSTR(email, 1, INSTR(email, '@') - 1), 'active', created, created
        FROM users
    """)

    # 7. Ensure every user has at least the 'student' role if no role assigned
    student_role_id = role_rows.get("student")
    if student_role_id:
        db_conn.execute("""
            INSERT OR IGNORE INTO user_roles(user_id, role_id, created_at)
            SELECT id, ?, ? FROM users
            WHERE id NOT IN (SELECT user_id FROM user_roles)
        """, (student_role_id, time.time()))

    db_conn.commit()


# ==============================================================================
# Authorization & Security Helpers (Server-Enforced)
# ==============================================================================

def get_current_user_id():
    """Returns the authenticated user ID from session or None."""
    return session.get("uid")


def get_user_roles(uid, institution_id=None):
    """
    Returns list of role slugs for the given user.
    Never trusts browser input; always resolves from the database.
    """
    if not uid:
        return []
    from app import db
    conn = db()
    query = """
        SELECT r.slug, ur.institution_id
        FROM user_roles ur
        JOIN roles r ON ur.role_id = r.id
        WHERE ur.user_id = ?
    """
    params = [uid]
    if institution_id:
        query += " AND (ur.institution_id IS NULL OR ur.institution_id = ?)"
        params.append(institution_id)

    rows = conn.execute(query, params).fetchall()
    return [r["slug"] for r in rows]


def get_user_permissions(uid, institution_id=None):
    """
    Computes the effective set of permissions for a user across all assigned roles.
    """
    roles = get_user_roles(uid, institution_id)
    if "super_admin" in roles:
        return set(PERMISSIONS.keys())

    perms = set()
    for role in roles:
        perms.update(ROLE_PERMISSIONS.get(role, []))
    return perms


def has_permission(uid, permission_slug, institution_id=None):
    """
    Returns True if user has the specified permission.
    Super Admins automatically satisfy all permissions.
    """
    if not uid:
        return False
    user_perms = get_user_permissions(uid, institution_id)
    return permission_slug in user_perms


def has_role(uid, role_slug, institution_id=None):
    """Returns True if the user holds the given role."""
    roles = get_user_roles(uid, institution_id)
    return role_slug in roles


def can_manage_user_role(actor_uid, target_uid, new_role_slug):
    """
    Enforces strict privilege boundaries:
    - Users cannot modify their own roles.
    - Only Super Admin can assign the 'super_admin' role.
    - Institution Admins can only assign roles within their level (teacher, student).
    """
    if not actor_uid or not target_uid:
        return False, "Invalid user specified."

    if actor_uid == target_uid:
        return False, "You cannot modify your own role or elevate your own privileges."

    actor_roles = get_user_roles(actor_uid)
    if "super_admin" in actor_roles:
        return True, "Authorized."

    if new_role_slug == "super_admin":
        return False, "Only an active Super Admin can assign the Super Admin role."

    if "institution_admin" in actor_roles:
        if new_role_slug in ("teacher", "student", "moderator_support"):
            return True, "Authorized."
        return False, "Institution Admins cannot grant elevated administrative privileges."

    return False, "Unauthorized to assign roles."


def can_access_document(uid, did, write=False):
    """
    Enforces strict cross-user document isolation:
    - Document Owner: full read & write access.
    - Super Admin: full read access (and write for moderation takedown).
    - Moderator: read access for moderation review.
    - Classroom Student/Teacher: read access IF document is explicitly shared with their classroom.
    """
    if not uid:
        return False, None
    from app import db
    conn = db()

    doc = conn.execute("SELECT * FROM docs WHERE id = ?", (did,)).fetchone()
    if not doc:
        return False, None

    # 1. Document Owner
    if doc["user_id"] == uid:
        return True, doc

    # If write access is required and user is not owner, only super_admin can delete
    actor_roles = get_user_roles(uid)
    if write:
        if "super_admin" in actor_roles:
            return True, doc
        return False, None

    # 2. Administrative / Moderation override
    if "super_admin" in actor_roles or "moderator_support" in actor_roles:
        return True, doc

    # 3. Classroom Sharing: check if document is shared with a classroom the user is enrolled in
    shared = conn.execute("""
        SELECT sd.id FROM shared_documents sd
        JOIN classroom_members cm ON sd.classroom_id = cm.classroom_id
        WHERE sd.doc_id = ? AND cm.user_id = ?
    """, (did, uid)).fetchone()

    if shared:
        return True, doc

    return False, None


# ==============================================================================
# Audit Logging (Protected & Append-Only)
# ==============================================================================

def log_audit(action, target_type=None, target_id=None, details=None, status="success"):
    """
    Safely records a security or administrative action to the audit_logs table.
    Captures user ID, IP address, user agent, and timestamp.
    """
    try:
        from app import db
        conn = db()
        uid = session.get("uid")
        ip = request.remote_addr if request else None
        ua = request.headers.get("User-Agent", "")[:250] if request else None

        details_str = json.dumps(details) if isinstance(details, (dict, list)) else (str(details) if details else None)

        conn.execute("""
            INSERT INTO audit_logs (user_id, action, target_type, target_id, ip_address, user_agent, details, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (uid, action, target_type, str(target_id) if target_id else None, ip, ua, details_str, status, time.time()))
        conn.commit()
    except Exception as e:
        # Failsafe: Audit failure shouldn't crash the entire request, but must be logged
        print(f"[SECURITY AUDIT FAILURE] Could not record audit log: {e}")


# ==============================================================================
# AI Usage & Cost Tracker
# ==============================================================================

# Estimated cost per 1,000 tokens ($)
COST_RATES = {
    "simple": 0.0001,       # Nano / 8B
    "standard": 0.0006,     # Super / 70B
    "complex": 0.0020,      # Ultra / 405B
    "embeddings": 0.00005,  # Embeddings
}

def track_ai_usage(uid, doc_id, kind, model, prompt_tokens=0, completion_tokens=0, latency_ms=0.0, error=None):
    """Records AI token consumption, latency, and estimated cost."""
    try:
        from app import db
        conn = db()
        rate = COST_RATES.get(kind, 0.0005)
        total_tok = (prompt_tokens or 0) + (completion_tokens or 0)
        cost_est = (total_tok / 1000.0) * rate

        conn.execute("""
            INSERT INTO ai_usage_events (user_id, doc_id, kind, model, prompt_tokens, completion_tokens, latency_ms, cost_est, error, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (uid, doc_id, kind, model, prompt_tokens, completion_tokens, latency_ms, cost_est, error, time.time()))
        conn.commit()
    except Exception as e:
        print(f"[AI USAGE TRACK ERROR] Could not log usage event: {e}")


# ==============================================================================
# Feature Flags & Maintenance Gate
# ==============================================================================

def is_feature_enabled(key, uid=None):
    """Checks whether a feature flag is enabled for the current audience."""
    try:
        from app import db
        conn = db()
        row = conn.execute("SELECT is_enabled, audience FROM feature_flags WHERE key = ?", (key,)).fetchone()
        if not row:
            return True  # default open if unset
        if not row["is_enabled"]:
            return False

        if row["audience"] == "admin_only":
            if not uid:
                return False
            roles = get_user_roles(uid)
            return "super_admin" in roles or "institution_admin" in roles

        return True
    except Exception:
        return True


def is_maintenance_active(uid=None):
    """Returns True if platform maintenance mode is currently turned on."""
    try:
        from app import db
        conn = db()
        row = conn.execute("SELECT is_enabled, audience FROM feature_flags WHERE key = 'maintenance_mode'").fetchone()
        if not row or not row["is_enabled"]:
            return False

        if uid:
            roles = get_user_roles(uid)
            if "super_admin" in roles or "institution_admin" in roles:
                return False  # Administrators bypass maintenance mode

        return True
    except Exception:
        return False


# ==============================================================================
# Declarative Decorators for Route Handlers
# ==============================================================================

def permission_required(permission_slug):
    """
    Decorator requiring the authenticated user to possess a specific permission.
    Returns 403 Forbidden with security audit log if unauthorized.
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            uid = session.get("uid")
            if not uid:
                flash("Authentication required to access this resource.")
                return redirect(url_for("login"))

            # Check if user account is deactivated
            from app import db
            profile = db().execute("SELECT status FROM profiles WHERE user_id = ?", (uid,)).fetchone()
            if profile and profile["status"] == "deactivated":
                log_audit("deactivated_user_access_attempt", target_type="user", target_id=uid, status="denied")
                session.clear()
                flash("Your account has been deactivated. Please contact support.")
                return redirect(url_for("login"))

            if not has_permission(uid, permission_slug):
                log_audit(
                    action="permission_denied",
                    target_type="permission",
                    target_id=permission_slug,
                    details={"path": request.path, "method": request.method},
                    status="denied"
                )
                if request.is_json or request.path.startswith("/api/"):
                    return jsonify(error="Access denied: Insufficient privileges.", permission=permission_slug), 403
                return render_template("admin/unauthorized.html", permission=permission_slug), 403

            return f(*args, **kwargs)
        return wrapper
    return decorator


def role_required(*allowed_roles):
    """Decorator requiring the user to hold at least one of the specified roles."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            uid = session.get("uid")
            if not uid:
                return redirect(url_for("login"))

            roles = get_user_roles(uid)
            if "super_admin" in roles or any(r in roles for r in allowed_roles):
                return f(*args, **kwargs)

            log_audit(
                action="role_access_denied",
                target_type="roles",
                target_id=",".join(allowed_roles),
                details={"path": request.path},
                status="denied"
            )
            if request.is_json or request.path.startswith("/api/"):
                return jsonify(error="Access denied: Required role missing.", roles=allowed_roles), 403
            return render_template("admin/unauthorized.html", roles=allowed_roles), 403
        return wrapper
    return decorator
