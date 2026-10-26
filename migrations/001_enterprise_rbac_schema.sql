-- ==============================================================================
-- PadhanaAI Database Migration: 001_enterprise_rbac_schema.sql
-- SQLite / Postgres compatible Enterprise RBAC, Moderation, and Classroom Schema
-- ==============================================================================

-- 1. Profiles Table (Extends base users)
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

-- 2. Roles Table
CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    is_system INTEGER DEFAULT 1
);

-- 3. Permissions Table
CREATE TABLE IF NOT EXISTS permissions (
    id INTEGER PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT
);

-- 4. Role Permissions Mapping
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    PRIMARY KEY(role_id, permission_id),
    FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY(permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);

-- 5. User Roles (Central server-enforced role assignments)
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

-- 6. Institutions
CREATE TABLE IF NOT EXISTS institutions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    domain TEXT,
    status TEXT DEFAULT 'active' CHECK(status IN ('active', 'inactive')),
    created_at REAL
);

-- 7. Classrooms
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

-- 8. Classroom Members (Rosters)
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

-- 9. Shared Documents (Classroom level material sharing)
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

-- 10. Audit Logs (Append-only security log)
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

-- 11. Feature Flags & Maintenance Mode
CREATE TABLE IF NOT EXISTS feature_flags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    is_enabled INTEGER DEFAULT 1,
    audience TEXT DEFAULT 'all' CHECK(audience IN ('all', 'institution', 'beta', 'admin_only')),
    updated_at REAL
);

-- 12. AI Model Configuration
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

-- 13. AI Usage & Cost Events
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

-- 14. Support & Feedback Tickets
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

-- 15. Document Moderation Reports
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

-- 16. Backup Snapshots Metadata
CREATE TABLE IF NOT EXISTS backup_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    size_bytes INTEGER,
    status TEXT DEFAULT 'completed',
    retention_days INTEGER DEFAULT 90,
    created_at REAL
);
