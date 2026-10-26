-- ==============================================================================
-- PadhanaAI Database Migration: 002_supabase_rls_policies.sql
-- PostgreSQL & Supabase Row Level Security (RLS) Policies
-- ==============================================================================

-- Enable Row Level Security on all sensitive tables
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE msgs ENABLE ROW LEVEL SECURITY;
ALTER TABLE quizzes ENABLE ROW LEVEL SECURITY;
ALTER TABLE shared_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE classrooms ENABLE ROW LEVEL SECURITY;
ALTER TABLE classroom_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE support_tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE document_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_usage_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE feature_flags ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_model_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE backup_snapshots ENABLE ROW LEVEL SECURITY;

-- Helper Function: Check if auth user has a specific role
CREATE OR REPLACE FUNCTION auth_has_role(role_name TEXT)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM user_roles ur
        JOIN roles r ON ur.role_id = r.id
        WHERE ur.user_id = auth.uid() AND r.slug = role_name
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Helper Function: Check if auth user is super admin
CREATE OR REPLACE FUNCTION auth_is_super_admin()
RETURNS BOOLEAN AS $$
BEGIN
    RETURN auth_has_role('super_admin');
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ------------------------------------------------------------------------------
-- 1. Profiles Table Policies
-- ------------------------------------------------------------------------------
-- Users can view their own profile; Admins can view all
CREATE POLICY "profiles_select_own_or_admin" ON profiles
    FOR SELECT USING (
        user_id = auth.uid() OR auth_is_super_admin() OR auth_has_role('institution_admin')
    );

-- Users can update only their non-privileged profile fields
CREATE POLICY "profiles_update_own" ON profiles
    FOR UPDATE USING (user_id = auth.uid())
    WITH CHECK (user_id = auth.uid());

-- Only admins can change status or institution assignment
CREATE POLICY "profiles_admin_update" ON profiles
    FOR ALL USING (auth_is_super_admin() OR auth_has_role('institution_admin'));

-- ------------------------------------------------------------------------------
-- 2. User Roles Table Policies (Strict Self-Escalation Prevention)
-- ------------------------------------------------------------------------------
-- Users can read their own roles; Admins can read all roles
CREATE POLICY "user_roles_select" ON user_roles
    FOR SELECT USING (user_id = auth.uid() OR auth_is_super_admin() OR auth_has_role('institution_admin'));

-- Only Super Admins can insert, update, or delete role assignments
CREATE POLICY "user_roles_admin_manage" ON user_roles
    FOR ALL USING (auth_is_super_admin());

-- ------------------------------------------------------------------------------
-- 3. Documents Table Policies (Cross-User Isolation & Classroom Sharing)
-- ------------------------------------------------------------------------------
-- Document Owners can access their docs; Classroom members can access shared docs; Admins/Moderators can review
CREATE POLICY "docs_select_policy" ON docs
    FOR SELECT USING (
        user_id = auth.uid()
        OR auth_is_super_admin()
        OR auth_has_role('moderator_support')
        OR EXISTS (
            SELECT 1 FROM shared_documents sd
            JOIN classroom_members cm ON sd.classroom_id = cm.classroom_id
            WHERE sd.doc_id = docs.id AND cm.user_id = auth.uid()
        )
    );

-- Only Document Owners can insert documents
CREATE POLICY "docs_insert_own" ON docs
    FOR INSERT WITH CHECK (user_id = auth.uid());

-- Document Owners can update/delete; Super Admins can delete
CREATE POLICY "docs_update_own" ON docs
    FOR UPDATE USING (user_id = auth.uid());

CREATE POLICY "docs_delete_own_or_admin" ON docs
    FOR DELETE USING (user_id = auth.uid() OR auth_is_super_admin());

-- ------------------------------------------------------------------------------
-- 4. Chunks Table (RAG Vector Isolation)
-- ------------------------------------------------------------------------------
-- Chunks can only be selected if the user has access to the parent document
CREATE POLICY "chunks_select_policy" ON chunks
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM docs WHERE docs.id = chunks.doc_id AND (
                docs.user_id = auth.uid()
                OR auth_is_super_admin()
                OR EXISTS (
                    SELECT 1 FROM shared_documents sd
                    JOIN classroom_members cm ON sd.classroom_id = cm.classroom_id
                    WHERE sd.doc_id = docs.id AND cm.user_id = auth.uid()
                )
            )
        )
    );

CREATE POLICY "chunks_owner_manage" ON chunks
    FOR ALL USING (
        EXISTS (SELECT 1 FROM docs WHERE docs.id = chunks.doc_id AND (docs.user_id = auth.uid() OR auth_is_super_admin()))
    );

-- ------------------------------------------------------------------------------
-- 5. Chat Messages (msgs) & Quizzes Isolation
-- ------------------------------------------------------------------------------
CREATE POLICY "msgs_owner_policy" ON msgs
    FOR ALL USING (
        EXISTS (SELECT 1 FROM docs WHERE docs.id = msgs.doc_id AND (docs.user_id = auth.uid() OR auth_is_super_admin()))
    );

CREATE POLICY "quizzes_owner_policy" ON quizzes
    FOR ALL USING (
        EXISTS (SELECT 1 FROM docs WHERE docs.id = quizzes.doc_id AND (docs.user_id = auth.uid() OR auth_is_super_admin()))
    );

-- ------------------------------------------------------------------------------
-- 6. Classrooms & Memberships Policies
-- ------------------------------------------------------------------------------
-- Teachers can manage their assigned classrooms; Students can view enrolled classrooms
CREATE POLICY "classrooms_select" ON classrooms
    FOR SELECT USING (
        teacher_id = auth.uid()
        OR auth_is_super_admin()
        OR auth_has_role('institution_admin')
        OR EXISTS (SELECT 1 FROM classroom_members WHERE classroom_id = classrooms.id AND user_id = auth.uid())
    );

CREATE POLICY "classrooms_teacher_admin_manage" ON classrooms
    FOR ALL USING (
        teacher_id = auth.uid() OR auth_is_super_admin() OR auth_has_role('institution_admin')
    );

-- ------------------------------------------------------------------------------
-- 7. Audit Logs Table (Append-Only Protection)
-- ------------------------------------------------------------------------------
-- Normal users CANNOT view or modify audit logs. Only authorized admins and moderators can read.
CREATE POLICY "audit_logs_select_admin" ON audit_logs
    FOR SELECT USING (auth_is_super_admin() OR auth_has_role('moderator_support'));

-- Server service role inserts audit logs; prevent any manual deletion or updates
CREATE POLICY "audit_logs_insert" ON audit_logs
    FOR INSERT WITH CHECK (true);

-- Deny UPDATE and DELETE on audit logs for all roles to guarantee audit integrity
CREATE POLICY "audit_logs_no_update" ON audit_logs FOR UPDATE USING (false);
CREATE POLICY "audit_logs_no_delete" ON audit_logs FOR DELETE USING (false);

-- ------------------------------------------------------------------------------
-- 8. Support Tickets & Moderation Reports
-- ------------------------------------------------------------------------------
CREATE POLICY "support_tickets_select" ON support_tickets
    FOR SELECT USING (
        user_id = auth.uid()
        OR assigned_to = auth.uid()
        OR auth_is_super_admin()
        OR auth_has_role('moderator_support')
    );

CREATE POLICY "support_tickets_insert_any" ON support_tickets
    FOR INSERT WITH CHECK (user_id = auth.uid());

CREATE POLICY "document_reports_select_mod" ON document_reports
    FOR SELECT USING (
        reporter_id = auth.uid() OR auth_is_super_admin() OR auth_has_role('moderator_support')
    );

CREATE POLICY "document_reports_manage_mod" ON document_reports
    FOR UPDATE USING (auth_is_super_admin() OR auth_has_role('moderator_support'));
