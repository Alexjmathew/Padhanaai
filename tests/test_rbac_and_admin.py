"""
PadhanaAI Enterprise RBAC & Security Test Suite
Covers role permissions, unauthorized access prevention, cross-user document isolation,
privilege escalation guards, and audit logging.
"""

import os
import unittest
import json
import sqlite3
import time
from werkzeug.security import generate_password_hash

# Ensure test uses an isolated database
TEST_DB = "data/test_app.db"
os.environ["SECRET_KEY"] = "test-secret-key-enterprise-security"

import app as flask_app
import rbac


class TestEnterpriseRBAC(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Configure app for testing
        flask_app.app.config["TESTING"] = True
        flask_app.app.config["WTF_CSRF_ENABLED"] = False

    def setUp(self):
        # Open SQLite test database and ensure schema
        self.conn = sqlite3.connect(TEST_DB)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(flask_app.SCHEMA)
        rbac.init_rbac_db(self.conn)

        # Truncate tables for a clean test run
        for tbl in ["audit_logs", "ai_usage_events", "document_reports", "support_tickets", "shared_documents", "classroom_members", "classrooms", "institutions", "user_roles", "profiles", "chunks", "msgs", "quizzes", "docs", "users"]:
            self.conn.execute(f"DELETE FROM {tbl}")
        # Patch db module to point to isolated test database
        import db as db_module
        db_module.DB_PATH = TEST_DB
        self.original_get_db = db_module.get_db

        def get_test_db():
            conn = sqlite3.connect(TEST_DB)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            return conn

        db_module.get_db = get_test_db
        db_module.db = get_test_db
        flask_app.db = get_test_db
        rbac.db = get_test_db

        self.client = flask_app.app.test_client()

        # Seed Users:
        # 1. super_admin (id=1)
        # 2. inst_admin (id=2)
        # 3. teacher_alice (id=3)
        # 4. student_bob (id=4)
        # 5. student_charlie (id=5)
        # 6. moderator_dave (id=6)
        now = time.time()
        users_to_seed = [
            (1, "super@padhana.ai", "super_admin"),
            (2, "admin@oxford.edu", "institution_admin"),
            (3, "teacher@oxford.edu", "teacher"),
            (4, "bob@oxford.edu", "student"),
            (5, "charlie@external.edu", "student"),
            (6, "mod@padhana.ai", "moderator_support"),
        ]

        for uid, email, role_slug in users_to_seed:
            self.conn.execute("INSERT INTO users(id, email, pw, created) VALUES(?, ?, ?, ?)",
                              (uid, email, generate_password_hash("password123"), now))
            self.conn.execute("INSERT INTO profiles(user_id, full_name, status, created_at, updated_at) VALUES(?, ?, 'active', ?, ?)",
                              (uid, email.split("@")[0].title(), now, now))
            role_id = self.conn.execute("SELECT id FROM roles WHERE slug = ?", (role_slug,)).fetchone()["id"]
            self.conn.execute("INSERT INTO user_roles(user_id, role_id, created_at) VALUES(?, ?, ?)",
                              (uid, role_id, now))

        # Seed a test document belonging to Student Bob (user_id=4)
        self.conn.execute("INSERT INTO docs(id, user_id, title, pages, status, created) VALUES(101, 4, 'Bobs_Quantum_Physics.pdf', 5, 'ready', ?)", (now,))
        self.conn.execute("INSERT INTO chunks(doc_id, page, text, emb) VALUES(101, 1, 'Quantum entanglement is a physical phenomenon.', NULL)")

        # Seed a test document belonging to Teacher Alice (user_id=3)
        self.conn.execute("INSERT INTO docs(id, user_id, title, pages, status, created) VALUES(202, 3, 'Alices_Lecture_Slides.pdf', 10, 'ready', ?)", (now,))
        self.conn.execute("INSERT INTO chunks(doc_id, page, text, emb) VALUES(202, 1, 'Welcome to CS401. Neural networks learn representations.', NULL)")

        # Create Institution and Classroom
        self.conn.execute("INSERT INTO institutions(id, name, slug, status, created_at) VALUES(1, 'Oxford University', 'oxford', 'active', ?)", (now,))
        self.conn.execute("INSERT INTO classrooms(id, institution_id, name, code, teacher_id, created_at) VALUES(1, 1, 'CS401 Deep Learning', 'CS401', 3, ?)", (now,))
        # Enroll Student Bob (user_id=4) in classroom 1
        self.conn.execute("INSERT INTO classroom_members(classroom_id, user_id, role, joined_at) VALUES(1, 4, 'student', ?)", (now,))
        # Share Teacher Alice's document with classroom 1
        self.conn.execute("INSERT INTO shared_documents(doc_id, classroom_id, shared_by, created_at) VALUES(202, 1, 3, ?)", (now,))

        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        import db as db_module
        if hasattr(self, 'original_get_db'):
            db_module.get_db = self.original_get_db
            db_module.db = self.original_get_db
            flask_app.db = self.original_get_db
            rbac.db = self.original_get_db

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(TEST_DB):
            try:
                os.remove(TEST_DB)
            except Exception:
                pass

    # ==========================================================================
    # 1. Role & Permission Matrix Tests
    # ==========================================================================

    def test_super_admin_has_all_permissions(self):
        """Super Admin must satisfy every system permission."""
        for perm in rbac.PERMISSIONS.keys():
            self.assertTrue(rbac.has_permission(1, perm), f"Super Admin should have {perm}")

    def test_student_restricted_permissions(self):
        """Students must only have basic read/upload permissions and cannot view admin or audit logs."""
        self.assertTrue(rbac.has_permission(4, "documents.read_own"))
        self.assertTrue(rbac.has_permission(4, "documents.upload"))
        self.assertFalse(rbac.has_permission(4, "users.view"))
        self.assertFalse(rbac.has_permission(4, "users.role_assign"))
        self.assertFalse(rbac.has_permission(4, "audit.view"))
        self.assertFalse(rbac.has_permission(4, "features.manage"))
        self.assertFalse(rbac.has_permission(4, "backups.manage"))

    def test_moderator_permissions(self):
        """Moderators have moderation and ticket access, but cannot assign roles or feature flags."""
        self.assertTrue(rbac.has_permission(6, "moderation.view"))
        self.assertTrue(rbac.has_permission(6, "moderation.action"))
        self.assertTrue(rbac.has_permission(6, "support.manage"))
        self.assertFalse(rbac.has_permission(6, "users.role_assign"))
        self.assertFalse(rbac.has_permission(6, "features.manage"))

    # ==========================================================================
    # 2. Unauthorized Access & Route Protection Tests
    # ==========================================================================

    def test_unauthenticated_user_cannot_access_admin(self):
        """Anonymous requests to /admin must be redirected to /login."""
        res = self.client.get("/admin/overview")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/login", res.headers["Location"])

    def test_student_forbidden_from_admin_portal(self):
        """Student (role=student) requesting /admin must receive 403 Forbidden."""
        with self.client.session_transaction() as sess:
            sess["uid"] = 4  # Bob (student)

        res = self.client.get("/admin/overview")
        self.assertEqual(res.status_code, 403)

    def test_teacher_forbidden_from_user_management(self):
        """Teachers cannot access the global User & Role Management module."""
        with self.client.session_transaction() as sess:
            sess["uid"] = 3  # Alice (teacher)

        res = self.client.get("/admin/users")
        self.assertEqual(res.status_code, 403)

    def test_super_admin_can_access_admin_portal(self):
        """Super Admin can access all admin routes successfully (200 OK)."""
        with self.client.session_transaction() as sess:
            sess["uid"] = 1  # Super Admin

        res = self.client.get("/admin/overview")
        self.assertEqual(res.status_code, 200)

        res_users = self.client.get("/admin/users")
        self.assertEqual(res_users.status_code, 200)

        res_audit = self.client.get("/admin/audit")
        self.assertEqual(res_audit.status_code, 200)

    # ==========================================================================
    # 3. Privilege Escalation Prevention Tests
    # ==========================================================================

    def test_user_cannot_modify_own_role(self):
        """Self-privilege escalation must be blocked server-side."""
        allowed, msg = rbac.can_manage_user_role(actor_uid=4, target_uid=4, new_role_slug="super_admin")
        self.assertFalse(allowed)
        self.assertIn("cannot modify your own role", msg)

    def test_institution_admin_cannot_assign_super_admin(self):
        """Non-Super Admins cannot grant the super_admin role."""
        allowed, msg = rbac.can_manage_user_role(actor_uid=2, target_uid=4, new_role_slug="super_admin")
        self.assertFalse(allowed)
        self.assertIn("Only an active Super Admin", msg)

    def test_super_admin_can_assign_roles(self):
        """Super Admin can assign roles to other users."""
        allowed, msg = rbac.can_manage_user_role(actor_uid=1, target_uid=4, new_role_slug="teacher")
        self.assertTrue(allowed)

    # ==========================================================================
    # 4. Cross-User Document Isolation & RAG Vector Security Tests
    # ==========================================================================

    def test_student_cannot_access_unshared_foreign_document(self):
        """Student Charlie (id=5) must NOT be able to view Student Bob's private document (101)."""
        allowed, doc = rbac.can_access_document(uid=5, did=101)
        self.assertFalse(allowed)

        with self.client.session_transaction() as sess:
            sess["uid"] = 5
        res = self.client.get("/doc/101")
        self.assertIn(res.status_code, (403, 404))

    def test_student_cannot_delete_foreign_document(self):
        """Student Charlie (id=5) attempting to delete Bob's document (101) is denied."""
        allowed, doc = rbac.can_access_document(uid=5, did=101, write=True)
        self.assertFalse(allowed)

    def test_classroom_member_can_access_shared_document(self):
        """Student Bob (id=4) is in classroom 1, where Alice shared doc 202. Bob should have read access."""
        allowed, doc = rbac.can_access_document(uid=4, did=202)
        self.assertTrue(allowed)
        self.assertIsNotNone(doc)

    def test_non_classroom_member_cannot_access_shared_document(self):
        """Student Charlie (id=5) is NOT in classroom 1. Charlie must NOT have access to doc 202."""
        allowed, doc = rbac.can_access_document(uid=5, did=202)
        self.assertFalse(allowed)

    # ==========================================================================
    # 5. Audit Logging Verification Tests
    # ==========================================================================

    def test_security_audit_logging(self):
        """Audit logging must append events and be searchable."""
        with flask_app.app.test_request_context():
            rbac.log_audit("test_permission_change", target_type="user", target_id=4, details={"role": "teacher"})

        conn = flask_app.db()
        log = conn.execute("SELECT * FROM audit_logs WHERE action = 'test_permission_change'").fetchone()
        self.assertIsNotNone(log)
        self.assertEqual(log["target_id"], "4")


if __name__ == "__main__":
    unittest.main()
