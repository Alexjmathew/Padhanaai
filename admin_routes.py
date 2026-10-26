"""
PadhanaAI Enterprise Admin Dashboard & Security Blueprint
Enforcing authorization across all ten functional enterprise modules.
"""

import os
import json
import time
import shutil
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, session, abort, send_file
from db import get_db as db
import rbac
from rbac import (
    permission_required, role_required, has_permission, has_role,
    get_user_roles, can_manage_user_role, log_audit, ROLES, PERMISSIONS, ROLE_PERMISSIONS
)

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


# ==============================================================================
# Helper Context & Navigation Generator
# ==============================================================================

@admin_bp.before_request
def verify_admin_access():
    """Guarantees that only authenticated users with administrative or staff roles can enter."""
    uid = session.get("uid")
    if not uid:
        flash("Please sign in to access the management portal.")
        return redirect(url_for("login"))

    roles = get_user_roles(uid)
    allowed = {"super_admin", "institution_admin", "moderator_support", "teacher"}
    if not (allowed & set(roles)):
        log_audit("unauthorized_admin_portal_access", target_type="admin", target_id=uid, status="denied")
        return render_template("admin/unauthorized.html", roles=list(allowed)), 403


@admin_bp.context_processor
def inject_admin_context():
    """Injects user roles, permissions, and navigation items into admin templates."""
    uid = session.get("uid")
    roles = get_user_roles(uid) if uid else []
    perms = rbac.get_user_permissions(uid) if uid else set()

    # Dynamic navigation items based on user permissions
    nav_modules = [
        {"id": "overview", "title": "Overview", "icon": "layout-dashboard", "url": url_for("admin.overview"), "perm": "analytics.view"},
        {"id": "users", "title": "Users & Roles", "icon": "users", "url": url_for("admin.users"), "perm": "users.view"},
        {"id": "analytics", "title": "Platform Analytics", "icon": "bar-chart-3", "url": url_for("admin.analytics"), "perm": "analytics.view"},
        {"id": "ai_usage", "title": "AI Usage & Costs", "icon": "cpu", "url": url_for("admin.ai_usage"), "perm": "ai_usage.view"},
        {"id": "moderation", "title": "Content Moderation", "icon": "shield-alert", "url": url_for("admin.moderation"), "perm": "moderation.view"},
        {"id": "audit", "title": "Security & Audit Logs", "icon": "shield-check", "url": url_for("admin.audit_logs_view"), "perm": "audit.view"},
        {"id": "feature_flags", "title": "Feature Flags", "icon": "toggle-right", "url": url_for("admin.feature_flags_view"), "perm": "features.manage"},
        {"id": "ai_config", "title": "AI Configuration", "icon": "sliders", "url": url_for("admin.ai_config_view"), "perm": "ai_config.manage"},
        {"id": "support", "title": "Support & Feedback", "icon": "life-buoy", "url": url_for("admin.support_view"), "perm": "support.view"},
        {"id": "backups", "title": "Backup & Retention", "icon": "database", "url": url_for("admin.backups_view"), "perm": "backups.view"},
        {"id": "institutions", "title": "Institutions & Classes", "icon": "school", "url": url_for("admin.institutions_view"), "perm": "classrooms.view"},
    ]

    # Filter navigation items by granted permissions
    accessible_nav = [m for m in nav_modules if "super_admin" in roles or m["perm"] in perms]

    return dict(
        admin_roles=roles,
        admin_perms=perms,
        nav_modules=accessible_nav,
        is_super_admin=("super_admin" in roles)
    )


# ==============================================================================
# Module 2 & Root: Platform Overview & High-Level KPIs
# ==============================================================================

@admin_bp.route("/")
@admin_bp.route("/overview")
@permission_required("analytics.view")
def overview():
    conn = db()

    # Core Metrics
    total_users = conn.execute("SELECT count(*) FROM users").fetchone()[0]
    active_users_7d = conn.execute("SELECT count(DISTINCT user_id) FROM ai_usage_events WHERE created_at > ?", (time.time() - 7*86400,)).fetchone()[0] or 1
    total_docs = conn.execute("SELECT count(*) FROM docs").fetchone()[0]
    total_pages = conn.execute("SELECT sum(pages) FROM docs").fetchone()[0] or 0
    total_ai_reqs = conn.execute("SELECT count(*) FROM ai_usage_events").fetchone()[0]
    total_quizzes = conn.execute("SELECT count(*) FROM quizzes").fetchone()[0]
    pending_reports = conn.execute("SELECT count(*) FROM document_reports WHERE status='pending'").fetchone()[0]
    open_tickets = conn.execute("SELECT count(*) FROM support_tickets WHERE status IN ('open', 'in_progress')").fetchone()[0]

    # Estimated Total Cost
    cost_row = conn.execute("SELECT sum(cost_est) FROM ai_usage_events").fetchone()
    total_cost = round(cost_row[0] or 0.0, 4)

    # Recent Audit Log Activity
    recent_logs = conn.execute("""
        SELECT a.*, u.email as user_email
        FROM audit_logs a
        LEFT JOIN users u ON a.user_id = u.id
        ORDER BY a.created_at DESC LIMIT 8
    """).fetchall()

    return render_template(
        "admin/overview.html",
        total_users=total_users,
        active_users_7d=active_users_7d,
        total_docs=total_docs,
        total_pages=total_pages,
        total_ai_reqs=total_ai_reqs,
        total_quizzes=total_quizzes,
        pending_reports=pending_reports,
        open_tickets=open_tickets,
        total_cost=total_cost,
        recent_logs=recent_logs
    )


# ==============================================================================
# Module 1: User and Role Management
# ==============================================================================

@admin_bp.route("/users")
@permission_required("users.view")
def users():
    conn = db()
    q = request.args.get("q", "").strip()
    role_filter = request.args.get("role", "")
    status_filter = request.args.get("status", "")

    query = """
        SELECT u.id, u.email, u.created,
               COALESCE(p.full_name, SUBSTR(u.email, 1, INSTR(u.email, '@') - 1)) as full_name,
               COALESCE(p.status, 'active') as status,
               COALESCE(i.name, 'Independent') as institution_name,
               GROUP_CONCAT(r.slug) as role_slugs,
               GROUP_CONCAT(r.name) as role_names
        FROM users u
        LEFT JOIN profiles p ON u.id = p.user_id
        LEFT JOIN institutions i ON p.institution_id = i.id
        LEFT JOIN user_roles ur ON u.id = ur.user_id
        LEFT JOIN roles r ON ur.role_id = r.id
        WHERE 1=1
    """
    params = []

    if q:
        query += " AND (u.email LIKE ? OR p.full_name LIKE ?)"
        params.extend([f"%{q}%", f"%{q}%"])

    if status_filter:
        query += " AND p.status = ?"
        params.append(status_filter)

    query += " GROUP BY u.id ORDER BY u.created DESC"

    all_users = conn.execute(query, params).fetchall()

    # Filter in memory by role if specified
    filtered_users = []
    for u in all_users:
        u_roles = (u["role_slugs"] or "").split(",")
        if not role_filter or role_filter in u_roles:
            filtered_users.append(u)

    all_roles = conn.execute("SELECT slug, name, description FROM roles ORDER BY id").fetchall()

    return render_template(
        "admin/users.html",
        users=filtered_users,
        roles=all_roles,
        q=q,
        role_filter=role_filter,
        status_filter=status_filter,
        total_count=len(filtered_users)
    )


@admin_bp.route("/users/<int:target_uid>/role", methods=["POST"])
@permission_required("users.role_assign")
def assign_user_role(target_uid):
    actor_uid = session.get("uid")
    new_role_slug = request.form.get("role_slug", "").strip()

    allowed, reason = can_manage_user_role(actor_uid, target_uid, new_role_slug)
    if not allowed:
        log_audit("privilege_escalation_prevented", target_type="user", target_id=target_uid, details={"requested_role": new_role_slug, "reason": reason}, status="denied")
        flash(reason, "error")
        return redirect(url_for("admin.users"))

    conn = db()
    role_row = conn.execute("SELECT id FROM roles WHERE slug = ?", (new_role_slug,)).fetchone()
    if not role_row:
        flash("Invalid role specified.", "error")
        return redirect(url_for("admin.users"))

    # Update role
    conn.execute("DELETE FROM user_roles WHERE user_id = ?", (target_uid,))
    conn.execute("""
        INSERT INTO user_roles (user_id, role_id, assigned_by, created_at)
        VALUES (?, ?, ?, ?)
    """, (target_uid, role_row["id"], actor_uid, time.time()))
    conn.commit()

    log_audit("role_assigned", target_type="user", target_id=target_uid, details={"new_role": new_role_slug})
    flash(f"Role updated successfully to {new_role_slug.replace('_', ' ').title()}.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:target_uid>/status", methods=["POST"])
@permission_required("users.deactivate")
def toggle_user_status(target_uid):
    actor_uid = session.get("uid")
    new_status = request.form.get("status", "active")
    if new_status not in ("active", "deactivated", "suspended"):
        flash("Invalid status.", "error")
        return redirect(url_for("admin.users"))

    if actor_uid == target_uid and new_status != "active":
        flash("You cannot deactivate your own administrative account.", "error")
        return redirect(url_for("admin.users"))

    conn = db()
    conn.execute("""
        INSERT INTO profiles (user_id, status, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET status = ?, updated_at = ?
    """, (target_uid, new_status, time.time(), new_status, time.time()))
    conn.commit()

    log_audit("user_status_changed", target_type="user", target_id=target_uid, details={"new_status": new_status})
    flash(f"User account status changed to {new_status}.", "success")
    return redirect(url_for("admin.users"))


# ==============================================================================
# Module 2: Platform Analytics
# ==============================================================================

@admin_bp.route("/analytics")
@permission_required("analytics.view")
def analytics():
    conn = db()

    # Aggregate by days for the last 7 days
    now = time.time()
    day_seconds = 86400
    days_data = []

    for i in range(6, -1, -1):
        day_start = now - (i + 1) * day_seconds
        day_end = now - i * day_seconds
        date_str = time.strftime("%b %d", time.localtime(day_start))

        docs_count = conn.execute("SELECT count(*) FROM docs WHERE created >= ? AND created < ?", (day_start, day_end)).fetchone()[0]
        ai_count = conn.execute("SELECT count(*) FROM ai_usage_events WHERE created_at >= ? AND created_at < ?", (day_start, day_end)).fetchone()[0]
        quiz_count = conn.execute("SELECT count(*) FROM quizzes WHERE created >= ? AND created < ?", (day_start, day_end)).fetchone()[0]

        days_data.append({
            "date": date_str,
            "docs": docs_count,
            "ai": ai_count,
            "quizzes": quiz_count
        })

    # Top Most Active Study Documents
    popular_docs = conn.execute("""
        SELECT d.id, d.title, d.pages, u.email as owner_email, count(m.id) as msg_count
        FROM docs d
        JOIN users u ON d.user_id = u.id
        LEFT JOIN msgs m ON d.id = m.doc_id
        GROUP BY d.id
        ORDER BY msg_count DESC LIMIT 6
    """).fetchall()

    return render_template(
        "admin/analytics.html",
        days_data=days_data,
        popular_docs=popular_docs
    )


# ==============================================================================
# Module 3: AI Usage and Cost Monitor
# ==============================================================================

@admin_bp.route("/ai-usage")
@permission_required("ai_usage.view")
def ai_usage():
    conn = db()

    # Model Breakdown
    model_stats = conn.execute("""
        SELECT kind, count(*) as req_count, sum(prompt_tokens) as p_tokens,
               sum(completion_tokens) as c_tokens, avg(latency_ms) as avg_latency,
               sum(cost_est) as total_cost
        FROM ai_usage_events
        GROUP BY kind
    """).fetchall()

    # Recent AI Invocations
    recent_events = conn.execute("""
        SELECT e.*, u.email as user_email, d.title as doc_title
        FROM ai_usage_events e
        LEFT JOIN users u ON e.user_id = u.id
        LEFT JOIN docs d ON e.doc_id = d.id
        ORDER BY e.created_at DESC LIMIT 20
    """).fetchall()

    total_tokens = sum((m["p_tokens"] or 0) + (m["c_tokens"] or 0) for m in model_stats)
    total_cost = sum(m["total_cost"] or 0.0 for m in model_stats)

    return render_template(
        "admin/ai_usage.html",
        model_stats=model_stats,
        recent_events=recent_events,
        total_tokens=total_tokens,
        total_cost=round(total_cost, 4)
    )


# ==============================================================================
# Module 4: Document Moderation Center
# ==============================================================================

@admin_bp.route("/moderation")
@permission_required("moderation.view")
def moderation():
    conn = db()
    reports = conn.execute("""
        SELECT r.*, d.title as doc_title, d.status as doc_status,
               u.email as reporter_email, o.email as owner_email
        FROM document_reports r
        JOIN docs d ON r.doc_id = d.id
        JOIN users u ON r.reporter_id = u.id
        JOIN users o ON d.user_id = o.id
        ORDER BY r.created_at DESC
    """).fetchall()

    return render_template("admin/moderation.html", reports=reports)


@admin_bp.route("/moderation/<int:report_id>/action", methods=["POST"])
@permission_required("moderation.action")
def moderation_action(report_id):
    action = request.form.get("action", "")
    notes = request.form.get("notes", "").strip()
    actor_uid = session.get("uid")
    conn = db()

    report = conn.execute("SELECT * FROM document_reports WHERE id = ?", (report_id,)).fetchone()
    if not report:
        flash("Report not found.", "error")
        return redirect(url_for("admin.moderation"))

    if action == "takedown":
        conn.execute("UPDATE docs SET status = 'takedown' WHERE id = ?", (report["doc_id"],))
        conn.execute("""
            UPDATE document_reports
            SET status = 'takedown', notes = ?, resolved_by = ?, updated_at = ?
            WHERE id = ?
        """, (notes, actor_uid, time.time(), report_id))
        log_audit("document_takedown", target_type="doc", target_id=report["doc_id"], details={"report_id": report_id, "notes": notes})
        flash("Document taken down successfully.", "success")

    elif action == "dismiss":
        conn.execute("""
            UPDATE document_reports
            SET status = 'dismissed', notes = ?, resolved_by = ?, updated_at = ?
            WHERE id = ?
        """, (notes, actor_uid, time.time(), report_id))
        log_audit("document_report_dismissed", target_type="doc", target_id=report["doc_id"], details={"report_id": report_id})
        flash("Report dismissed.", "success")

    elif action == "restore":
        conn.execute("UPDATE docs SET status = 'ready' WHERE id = ?", (report["doc_id"],))
        conn.execute("""
            UPDATE document_reports
            SET status = 'reviewed', notes = ?, resolved_by = ?, updated_at = ?
            WHERE id = ?
        """, (notes, actor_uid, time.time(), report_id))
        log_audit("document_restored", target_type="doc", target_id=report["doc_id"], details={"report_id": report_id})
        flash("Document restored to active study status.", "success")

    conn.commit()
    return redirect(url_for("admin.moderation"))


# ==============================================================================
# Module 5: Security and Audit Logs
# ==============================================================================

@admin_bp.route("/audit")
@permission_required("audit.view")
def audit_logs_view():
    conn = db()
    action_filter = request.args.get("action", "").strip()
    user_filter = request.args.get("user", "").strip()

    query = """
        SELECT a.*, u.email as user_email
        FROM audit_logs a
        LEFT JOIN users u ON a.user_id = u.id
        WHERE 1=1
    """
    params = []
    if action_filter:
        query += " AND a.action = ?"
        params.append(action_filter)
    if user_filter:
        query += " AND u.email LIKE ?"
        params.append(f"%{user_filter}%")

    query += " ORDER BY a.created_at DESC LIMIT 100"
    logs = conn.execute(query, params).fetchall()

    actions_list = [r[0] for r in conn.execute("SELECT DISTINCT action FROM audit_logs").fetchall()]

    return render_template(
        "admin/audit.html",
        logs=logs,
        actions=actions_list,
        action_filter=action_filter,
        user_filter=user_filter
    )


# ==============================================================================
# Module 6: Feature Flags and Maintenance Mode
# ==============================================================================

@admin_bp.route("/feature-flags")
@permission_required("features.manage")
def feature_flags_view():
    conn = db()
    flags = conn.execute("SELECT * FROM feature_flags ORDER BY id").fetchall()
    return render_template("admin/feature_flags.html", flags=flags)


@admin_bp.route("/feature-flags/<key>/toggle", methods=["POST"])
@permission_required("features.manage")
def toggle_feature_flag(key):
    conn = db()
    row = conn.execute("SELECT is_enabled FROM feature_flags WHERE key = ?", (key,)).fetchone()
    if not row:
        flash("Feature flag does not exist.", "error")
        return redirect(url_for("admin.feature_flags_view"))

    new_val = 0 if row["is_enabled"] else 1
    new_audience = request.form.get("audience", "all")
    conn.execute("""
        UPDATE feature_flags
        SET is_enabled = ?, audience = ?, updated_at = ?
        WHERE key = ?
    """, (new_val, new_audience, time.time(), key))
    conn.commit()

    log_audit("feature_flag_changed", target_type="feature_flag", target_id=key, details={"enabled": new_val, "audience": new_audience})
    flash(f"Feature '{key}' updated successfully.", "success")
    return redirect(url_for("admin.feature_flags_view"))


# ==============================================================================
# Module 7: AI Model Configuration
# ==============================================================================

@admin_bp.route("/ai-config")
@permission_required("ai_config.manage")
def ai_config_view():
    conn = db()
    configs = conn.execute("SELECT * FROM ai_model_configs ORDER BY id").fetchall()
    return render_template("admin/ai_config.html", configs=configs)


@admin_bp.route("/ai-config/<tier>", methods=["POST"])
@permission_required("ai_config.manage")
def update_ai_config(tier):
    model_id = request.form.get("model_id", "").strip()
    max_tokens = int(request.form.get("max_tokens", 1200))
    temperature = float(request.form.get("temperature", 0.2))
    system_prompt = request.form.get("system_prompt", "").strip()

    conn = db()
    conn.execute("""
        UPDATE ai_model_configs
        SET model_id = ?, max_tokens = ?, temperature = ?, system_prompt = ?, updated_at = ?
        WHERE tier = ?
    """, (model_id, max_tokens, temperature, system_prompt, time.time(), tier))
    conn.commit()

    log_audit("ai_config_updated", target_type="ai_config", target_id=tier, details={"model_id": model_id, "max_tokens": max_tokens})
    flash(f"Configuration for '{tier.title()}' tier saved.", "success")
    return redirect(url_for("admin.ai_config_view"))


# ==============================================================================
# Module 8: Support and Feedback Manager
# ==============================================================================

@admin_bp.route("/support")
@permission_required("support.view")
def support_view():
    conn = db()
    tickets = conn.execute("""
        SELECT t.*, u.email as user_email, a.email as assignee_email
        FROM support_tickets t
        JOIN users u ON t.user_id = u.id
        LEFT JOIN users a ON t.assigned_to = a.id
        ORDER BY t.created_at DESC
    """).fetchall()

    staff_members = conn.execute("""
        SELECT u.id, u.email FROM users u
        JOIN user_roles ur ON u.id = ur.user_id
        JOIN roles r ON ur.role_id = r.id
        WHERE r.slug IN ('super_admin', 'moderator_support', 'institution_admin')
    """).fetchall()

    return render_template("admin/support.html", tickets=tickets, staff=staff_members)


@admin_bp.route("/support/<int:ticket_id>/status", methods=["POST"])
@permission_required("support.manage")
def update_ticket_status(ticket_id):
    status = request.form.get("status", "open")
    assigned_to = request.form.get("assigned_to") or None
    conn = db()

    conn.execute("""
        UPDATE support_tickets
        SET status = ?, assigned_to = ?, updated_at = ?
        WHERE id = ?
    """, (status, assigned_to, time.time(), ticket_id))
    conn.commit()

    log_audit("support_ticket_updated", target_type="support_ticket", target_id=ticket_id, details={"status": status, "assigned_to": assigned_to})
    flash("Ticket updated successfully.", "success")
    return redirect(url_for("admin.support_view"))


# ==============================================================================
# Module 9: Backup and Data Retention
# ==============================================================================

@admin_bp.route("/backups")
@permission_required("backups.view")
def backups_view():
    conn = db()
    snapshots = conn.execute("SELECT * FROM backup_snapshots ORDER BY created_at DESC").fetchall()
    db_size_mb = 0
    if os.path.exists("data/app.db"):
        db_size_mb = round(os.path.getsize("data/app.db") / (1024 * 1024), 2)

    return render_template(
        "admin/backups.html",
        snapshots=snapshots,
        db_size_mb=db_size_mb
    )


@admin_bp.route("/backups/create", methods=["POST"])
@permission_required("backups.manage")
def create_backup():
    os.makedirs("data/backups", exist_ok=True)
    snapshot_name = f"backup_snapshot_{time.strftime('%Y%m%d_%H%M%S')}.db"
    dest_path = os.path.join("data/backups", snapshot_name)

    try:
        shutil.copyfile("data/app.db", dest_path)
        size_bytes = os.path.getsize(dest_path)
        conn = db()
        conn.execute("""
            INSERT INTO backup_snapshots (name, size_bytes, status, retention_days, created_at)
            VALUES (?, ?, 'completed', 90, ?)
        """, (snapshot_name, size_bytes, time.time()))
        conn.commit()

        log_audit("backup_created", target_type="backup", target_id=snapshot_name, details={"size_bytes": size_bytes})
        flash(f"Snapshot '{snapshot_name}' created successfully.", "success")
    except Exception as e:
        flash(f"Backup failed: {e}", "error")

    return redirect(url_for("admin.backups_view"))


@admin_bp.route("/backups/download/<name>")
@permission_required("backups.manage")
def download_backup(name):
    # Sanitize file name to avoid directory traversal
    clean_name = os.path.basename(name)
    path = os.path.join("data/backups", clean_name)
    if not os.path.exists(path):
        abort(404)
    log_audit("backup_downloaded", target_type="backup", target_id=clean_name)
    return send_file(path, as_attachment=True, download_name=clean_name)


# ==============================================================================
# Module 10: Institution and Classroom Management
# ==============================================================================

@admin_bp.route("/institutions")
@permission_required("classrooms.view")
def institutions_view():
    conn = db()
    institutions_list = conn.execute("""
        SELECT i.*, count(DISTINCT c.id) as class_count, count(DISTINCT p.user_id) as member_count
        FROM institutions i
        LEFT JOIN classrooms c ON i.id = c.institution_id
        LEFT JOIN profiles p ON i.id = p.institution_id
        GROUP BY i.id
        ORDER BY i.created_at DESC
    """).fetchall()

    classrooms_list = conn.execute("""
        SELECT c.*, i.name as institution_name, u.email as teacher_email,
               count(cm.id) as student_count
        FROM classrooms c
        LEFT JOIN institutions i ON c.institution_id = i.id
        LEFT JOIN users u ON c.teacher_id = u.id
        LEFT JOIN classroom_members cm ON c.id = cm.classroom_id AND cm.role = 'student'
        GROUP BY c.id
        ORDER BY c.created_at DESC
    """).fetchall()

    teachers = conn.execute("""
        SELECT u.id, u.email FROM users u
        JOIN user_roles ur ON u.id = ur.user_id
        JOIN roles r ON ur.role_id = r.id
        WHERE r.slug IN ('teacher', 'institution_admin', 'super_admin')
    """).fetchall()

    return render_template(
        "admin/institutions.html",
        institutions=institutions_list,
        classrooms=classrooms_list,
        teachers=teachers
    )


@admin_bp.route("/institutions/create", methods=["POST"])
@permission_required("institutions.manage")
def create_institution():
    name = request.form.get("name", "").strip()
    domain = request.form.get("domain", "").strip()
    slug = name.lower().replace(" ", "-")[:40]

    if not name:
        flash("Institution name is required.", "error")
        return redirect(url_for("admin.institutions_view"))

    conn = db()
    try:
        conn.execute("""
            INSERT INTO institutions (name, slug, domain, status, created_at)
            VALUES (?, ?, ?, 'active', ?)
        """, (name, slug, domain, time.time()))
        conn.commit()
        log_audit("institution_created", target_type="institution", target_id=slug, details={"name": name, "domain": domain})
        flash(f"Institution '{name}' registered.", "success")
    except Exception as e:
        flash(f"Could not register institution: {e}", "error")

    return redirect(url_for("admin.institutions_view"))


@admin_bp.route("/classrooms/create", methods=["POST"])
@permission_required("classrooms.manage")
def create_classroom():
    name = request.form.get("name", "").strip()
    code = request.form.get("code", "").strip().upper()
    institution_id = request.form.get("institution_id") or None
    teacher_id = request.form.get("teacher_id") or session.get("uid")

    if not name or not code:
        flash("Classroom title and enrollment code are required.", "error")
        return redirect(url_for("admin.institutions_view"))

    conn = db()
    try:
        cur = conn.execute("""
            INSERT INTO classrooms (name, code, institution_id, teacher_id, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (name, code, institution_id, teacher_id, time.time()))

        # Add teacher as classroom member
        conn.execute("""
            INSERT INTO classroom_members (classroom_id, user_id, role, joined_at)
            VALUES (?, ?, 'teacher', ?)
        """, (cur.lastrowid, teacher_id, time.time()))

        conn.commit()
        log_audit("classroom_created", target_type="classroom", target_id=code, details={"name": name, "teacher_id": teacher_id})
        flash(f"Classroom '{name}' created with enrollment code '{code}'.", "success")
    except Exception as e:
        flash(f"Could not create classroom: {e}", "error")

    return redirect(url_for("admin.institutions_view"))
