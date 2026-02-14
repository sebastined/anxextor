-- ============================================
-- anxextor Database - Production Hardening
-- Date: 2026-02-14
-- Purpose: RLS, constraints, indexes, audit timestamps, and cleanup
-- ============================================

BEGIN;

-- ============================================
-- STEP 1: Enable RLS on all app tables
-- ============================================
-- NOTE: service_role bypasses RLS. If you use anon/authenticated keys directly,
-- you must add explicit policies before enabling RLS in production.

ALTER TABLE IF EXISTS public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.user_oauth_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.visitor_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.visitor_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.feedback_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.feedback_user_prefs ENABLE ROW LEVEL SECURITY;

-- Optional: lock down anon/authenticated access at the table level
REVOKE ALL ON TABLE public.users FROM anon, authenticated;
REVOKE ALL ON TABLE public.user_oauth_providers FROM anon, authenticated;
REVOKE ALL ON TABLE public.visitor_profiles FROM anon, authenticated;
REVOKE ALL ON TABLE public.visitor_events FROM anon, authenticated;
REVOKE ALL ON TABLE public.feedback_events FROM anon, authenticated;
REVOKE ALL ON TABLE public.feedback_user_prefs FROM anon, authenticated;

-- ============================================
-- STEP 2: Constraints and data quality checks
-- ============================================

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'users' AND column_name = 'role'
    ) AND NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_user_role'
    ) THEN
        ALTER TABLE public.users
            ADD CONSTRAINT chk_user_role
            CHECK (role IN ('user', 'manager', 'admin', 'super_admin'));
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'users' AND column_name = 'provider'
    ) AND NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_user_provider'
    ) THEN
        ALTER TABLE public.users
            ADD CONSTRAINT chk_user_provider
            CHECK (provider IN ('google', 'github'));
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'visitor_profiles' AND column_name = 'visit_count'
    ) AND NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_visit_count_nonnegative'
    ) THEN
        ALTER TABLE public.visitor_profiles
            ADD CONSTRAINT chk_visit_count_nonnegative
            CHECK (visit_count >= 0);
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'visitor_profiles' AND column_name = 'scan_count'
    ) AND NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_scan_count_nonnegative'
    ) THEN
        ALTER TABLE public.visitor_profiles
            ADD CONSTRAINT chk_scan_count_nonnegative
            CHECK (scan_count >= 0);
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'visitor_events' AND column_name = 'event_type'
    ) AND NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_event_type'
    ) THEN
        ALTER TABLE public.visitor_events
            ADD CONSTRAINT chk_event_type
            CHECK (event_type IN ('visit', 'scan'));
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'feedback_events' AND column_name = 'rating'
    ) AND NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_feedback_rating'
    ) THEN
        ALTER TABLE public.feedback_events
            ADD CONSTRAINT chk_feedback_rating
            CHECK (rating IN ('up', 'down'));
    END IF;
END $$;

-- ============================================
-- STEP 3: Indexes for API query paths
-- ============================================

CREATE INDEX IF NOT EXISTS idx_users_email ON public.users(email);
CREATE INDEX IF NOT EXISTS idx_users_last_active ON public.users(last_active);

CREATE INDEX IF NOT EXISTS idx_visitor_ip_hash ON public.visitor_profiles(ip_hash);
CREATE INDEX IF NOT EXISTS idx_visitor_last_visit ON public.visitor_profiles(last_visit_at DESC);

CREATE INDEX IF NOT EXISTS idx_visitor_events_fp_created
    ON public.visitor_events(fingerprint_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_visitor_events_type_created
    ON public.visitor_events(event_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_feedback_fp_created
    ON public.feedback_events(fingerprint_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_feedback_page_rating_created
    ON public.feedback_events(page, rating, created_at DESC);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'feedback_user_prefs'
    ) THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS idx_feedback_user_prefs_fp_page ON public.feedback_user_prefs (fingerprint_id, page)';
    END IF;
END $$;

-- ============================================
-- STEP 4: Audit timestamps
-- ============================================

ALTER TABLE public.users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP;
ALTER TABLE public.visitor_profiles ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP;

UPDATE public.users
SET updated_at = COALESCE(last_active, created_at)
WHERE updated_at IS NULL;

UPDATE public.visitor_profiles
SET updated_at = COALESCE(last_visit_at, created_at)
WHERE updated_at IS NULL;

CREATE OR REPLACE FUNCTION public.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS update_users_updated_at ON public.users;
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON public.users
    FOR EACH ROW
    EXECUTE FUNCTION public.update_updated_at_column();

DROP TRIGGER IF EXISTS update_visitor_profiles_updated_at ON public.visitor_profiles;
CREATE TRIGGER update_visitor_profiles_updated_at
    BEFORE UPDATE ON public.visitor_profiles
    FOR EACH ROW
    EXECUTE FUNCTION public.update_updated_at_column();

-- ============================================
-- STEP 5: Remove unused views
-- ============================================

DROP VIEW IF EXISTS public.active_users;
DROP VIEW IF EXISTS public.recently_active_users;

COMMIT;

-- ============================================
-- POST-RUN CHECKS
-- ============================================
-- Verify RLS enabled
-- SELECT relname, relrowsecurity FROM pg_class WHERE relname IN (
--   'users','user_oauth_providers','visitor_profiles','visitor_events','feedback_events','feedback_user_prefs'
-- );

-- Verify constraints
-- SELECT conname, conrelid::regclass FROM pg_constraint
-- WHERE conname IN ('chk_user_role','chk_user_provider','chk_visit_count_nonnegative',
--                   'chk_scan_count_nonnegative','chk_event_type','chk_feedback_rating');
