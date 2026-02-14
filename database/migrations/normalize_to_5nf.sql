-- ============================================
-- anxextor Database - 5NF Normalization Migration
-- Date: 2026-02-14
-- Purpose: Normalize users table to achieve 4NF/5NF compliance
-- ============================================

-- IMPORTANT: Run in Supabase SQL Editor
-- Backup database before running
-- Test in development first

BEGIN;

-- ============================================
-- STEP 1: Create OAuth Providers Table
-- ============================================
-- This fixes the 4NF violation where users can have multiple OAuth providers

CREATE TABLE IF NOT EXISTS user_oauth_providers (
    user_id VARCHAR(16) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(20) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    linked_at TIMESTAMP DEFAULT NOW(),
    last_used_at TIMESTAMP,
    is_primary BOOLEAN DEFAULT FALSE,
    PRIMARY KEY (user_id, provider),
    UNIQUE (provider, provider_user_id),
    CHECK (provider IN ('google', 'github', 'facebook', 'twitter', 'microsoft'))
);

COMMENT ON TABLE user_oauth_providers IS 'OAuth provider accounts linked to users (supports multiple providers per user)';
COMMENT ON COLUMN user_oauth_providers.provider IS 'OAuth provider name (google, github, etc.)';
COMMENT ON COLUMN user_oauth_providers.provider_user_id IS 'User ID from the OAuth provider';
COMMENT ON COLUMN user_oauth_providers.is_primary IS 'Whether this is the user''s primary login method';

-- ============================================
-- STEP 2: Migrate Existing OAuth Data
-- ============================================
-- Move google_id and github_id from users table to oauth_providers table

-- Insert Google OAuth data
INSERT INTO user_oauth_providers (user_id, provider, provider_user_id, linked_at, last_used_at, is_primary)
SELECT 
    id AS user_id,
    'google' AS provider,
    google_id AS provider_user_id,
    created_at AS linked_at,
    CASE 
        WHEN provider = 'google' THEN last_active 
        ELSE created_at 
    END AS last_used_at,
    CASE 
        WHEN provider = 'google' THEN TRUE 
        ELSE FALSE 
    END AS is_primary
FROM users
WHERE google_id IS NOT NULL
ON CONFLICT (user_id, provider) DO NOTHING;

-- Insert GitHub OAuth data
INSERT INTO user_oauth_providers (user_id, provider, provider_user_id, linked_at, last_used_at, is_primary)
SELECT 
    id AS user_id,
    'github' AS provider,
    github_id AS provider_user_id,
    created_at AS linked_at,
    CASE 
        WHEN provider = 'github' THEN last_active 
        ELSE created_at 
    END AS last_used_at,
    CASE 
        WHEN provider = 'github' THEN TRUE 
        ELSE FALSE 
    END AS is_primary
FROM users
WHERE github_id IS NOT NULL
ON CONFLICT (user_id, provider) DO NOTHING;

-- ============================================
-- STEP 3: Add Performance Indexes
-- ============================================

CREATE INDEX IF NOT EXISTS idx_oauth_provider ON user_oauth_providers(provider);
CREATE INDEX IF NOT EXISTS idx_oauth_last_used ON user_oauth_providers(last_used_at DESC);
CREATE INDEX IF NOT EXISTS idx_oauth_user_provider ON user_oauth_providers(user_id, provider);
CREATE INDEX IF NOT EXISTS idx_oauth_is_primary ON user_oauth_providers(user_id) WHERE is_primary = TRUE;

-- Add missing indexes on other tables
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_visitor_ip_hash ON visitor_profiles(ip_hash);
CREATE INDEX IF NOT EXISTS idx_visitor_last_visit ON visitor_profiles(last_visit_at DESC);

-- ============================================
-- STEP 4: Create Backward Compatibility View
-- ============================================
-- This view allows existing queries to work without changes

CREATE OR REPLACE VIEW users_with_oauth AS
SELECT 
    u.id,
    u.email,
    u.full_name,
    u.picture,
    u.role,
    u.is_suspended,
    u.scan_count,
    u.created_at,
    u.last_active,
    -- Legacy columns (for backward compatibility)
    MAX(CASE WHEN uop.provider = 'google' THEN uop.provider_user_id END) AS google_id,
    MAX(CASE WHEN uop.provider = 'github' THEN uop.provider_user_id END) AS github_id,
    -- New aggregated columns
    array_agg(DISTINCT uop.provider ORDER BY uop.provider) FILTER (WHERE uop.provider IS NOT NULL) AS providers,
    MAX(CASE WHEN uop.is_primary = TRUE THEN uop.provider END) AS primary_provider
FROM users u
LEFT JOIN user_oauth_providers uop ON u.id = uop.user_id
GROUP BY u.id, u.email, u.full_name, u.picture, u.role, u.is_suspended, u.scan_count, u.created_at, u.last_active;

COMMENT ON VIEW users_with_oauth IS 'Users with aggregated OAuth provider data (backward compatible)';

-- ============================================
-- STEP 5: Verify Data Integrity
-- ============================================
-- Run these queries to verify migration success

-- Check migrated Google OAuth data
DO $$
DECLARE
    google_count INTEGER;
    github_count INTEGER;
    user_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO user_count FROM users;
    SELECT COUNT(*) INTO google_count FROM users WHERE google_id IS NOT NULL;
    SELECT COUNT(*) INTO github_count FROM users WHERE github_id IS NOT NULL;
    
    RAISE NOTICE 'Total users: %', user_count;
    RAISE NOTICE 'Users with Google OAuth: %', google_count;
    RAISE NOTICE 'Users with GitHub OAuth: %', github_count;
    RAISE NOTICE 'OAuth provider records migrated: %', (SELECT COUNT(*) FROM user_oauth_providers);
END $$;

-- ============================================
-- STEP 6: Add Audit Columns (Optional)
-- ============================================

ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP;
ALTER TABLE visitor_profiles ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP;

-- Update existing rows
UPDATE users SET updated_at = COALESCE(last_active, created_at) WHERE updated_at IS NULL;
UPDATE visitor_profiles SET updated_at = COALESCE(last_visit_at, created_at) WHERE updated_at IS NULL;

-- Create trigger function for auto-updating timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create triggers
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_visitor_profiles_updated_at ON visitor_profiles;
CREATE TRIGGER update_visitor_profiles_updated_at 
    BEFORE UPDATE ON visitor_profiles 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================
-- STEP 7: Helper Functions
-- ============================================

-- Function to get user's primary OAuth provider
CREATE OR REPLACE FUNCTION get_primary_oauth_provider(p_user_id VARCHAR)
RETURNS VARCHAR AS $$
BEGIN
    RETURN (
        SELECT provider 
        FROM user_oauth_providers 
        WHERE user_id = p_user_id AND is_primary = TRUE 
        LIMIT 1
    );
END;
$$ LANGUAGE plpgsql STABLE;

-- Function to link new OAuth provider to user
CREATE OR REPLACE FUNCTION link_oauth_provider(
    p_user_id VARCHAR,
    p_provider VARCHAR,
    p_provider_user_id VARCHAR,
    p_set_as_primary BOOLEAN DEFAULT FALSE
)
RETURNS VOID AS $$
BEGIN
    -- If setting as primary, unset other primaries first
    IF p_set_as_primary THEN
        UPDATE user_oauth_providers 
        SET is_primary = FALSE 
        WHERE user_id = p_user_id;
    END IF;
    
    -- Insert or update the OAuth provider
    INSERT INTO user_oauth_providers (user_id, provider, provider_user_id, is_primary, last_used_at)
    VALUES (p_user_id, p_provider, p_provider_user_id, p_set_as_primary, NOW())
    ON CONFLICT (user_id, provider) 
    DO UPDATE SET 
        provider_user_id = EXCLUDED.provider_user_id,
        is_primary = EXCLUDED.is_primary,
        last_used_at = NOW();
END;
$$ LANGUAGE plpgsql;

-- Function to unlink OAuth provider
CREATE OR REPLACE FUNCTION unlink_oauth_provider(
    p_user_id VARCHAR,
    p_provider VARCHAR
)
RETURNS BOOLEAN AS $$
DECLARE
    provider_count INTEGER;
BEGIN
    -- Check if user has other providers
    SELECT COUNT(*) INTO provider_count 
    FROM user_oauth_providers 
    WHERE user_id = p_user_id;
    
    -- Don't allow unlinking if it's the only provider
    IF provider_count <= 1 THEN
        RAISE EXCEPTION 'Cannot unlink the only OAuth provider for user %', p_user_id;
        RETURN FALSE;
    END IF;
    
    -- Delete the provider
    DELETE FROM user_oauth_providers 
    WHERE user_id = p_user_id AND provider = p_provider;
    
    -- If we deleted the primary, set another as primary
    IF NOT EXISTS (SELECT 1 FROM user_oauth_providers WHERE user_id = p_user_id AND is_primary = TRUE) THEN
        WITH candidate AS (
            SELECT provider
            FROM user_oauth_providers
            WHERE user_id = p_user_id
            ORDER BY last_used_at DESC NULLS LAST
            LIMIT 1
        )
        UPDATE user_oauth_providers
        SET is_primary = TRUE
        WHERE user_id = p_user_id
          AND provider = (SELECT provider FROM candidate);
    END IF;
    
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

COMMIT;

-- ============================================
-- POST-MIGRATION VALIDATION QUERIES
-- ============================================
-- Run these after migration to verify success

-- Query 1: Check all users have at least one OAuth provider
SELECT 
    COUNT(*) AS users_without_oauth
FROM users u
LEFT JOIN user_oauth_providers uop ON u.id = uop.user_id
WHERE uop.user_id IS NULL;
-- Expected: 0

-- Query 2: Check all users have exactly one primary provider
SELECT 
    u.id,
    u.email,
    COUNT(*) FILTER (WHERE uop.is_primary = TRUE) AS primary_count
FROM users u
LEFT JOIN user_oauth_providers uop ON u.id = uop.user_id
GROUP BY u.id, u.email
HAVING COUNT(*) FILTER (WHERE uop.is_primary = TRUE) != 1;
-- Expected: 0 rows (all users should have exactly 1 primary)

-- Query 3: List users with multiple OAuth providers
SELECT 
    u.email,
    array_agg(uop.provider) AS providers,
    MAX(CASE WHEN uop.is_primary THEN uop.provider END) AS primary_provider
FROM users u
JOIN user_oauth_providers uop ON u.id = uop.user_id
GROUP BY u.id, u.email
HAVING COUNT(*) > 1;

-- Query 4: Verify data counts match
SELECT 
    'users' AS table_name, 
    COUNT(*) AS count 
FROM users
UNION ALL
SELECT 
    'user_oauth_providers', 
    COUNT(*) 
FROM user_oauth_providers
UNION ALL
SELECT 
    'Google OAuth records',
    COUNT(*) 
FROM users 
WHERE google_id IS NOT NULL
UNION ALL
SELECT 
    'GitHub OAuth records',
    COUNT(*) 
FROM users 
WHERE github_id IS NOT NULL;

-- ============================================
-- OPTIONAL: Remove Legacy Columns (Phase 2)
-- ============================================
-- ONLY run these after verifying application works with new schema
-- Uncomment when ready to complete migration

/*
-- Drop constraints first
ALTER TABLE users DROP CONSTRAINT IF EXISTS chk_user_provider;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_google_id_key;

-- Drop indexes on legacy columns
DROP INDEX IF EXISTS idx_users_github_id;

-- Remove legacy columns
ALTER TABLE users DROP COLUMN IF EXISTS google_id;
ALTER TABLE users DROP COLUMN IF EXISTS github_id;
ALTER TABLE users DROP COLUMN IF EXISTS provider;

-- Rename to clarify what it stores (optional)
COMMENT ON TABLE users IS 'User accounts (OAuth provider data now in user_oauth_providers table)';
*/

-- ============================================
-- MIGRATION COMPLETE
-- ============================================
-- Next Steps:
-- 1. Update backend/app/services/user_service.py to use user_oauth_providers
-- 2. Update OAuth callback endpoints to call link_oauth_provider()
-- 3. Test authentication flow with both Google and GitHub
-- 4. Monitor application logs for errors
-- 5. After 1 week of successful operation, run Phase 2 (remove legacy columns)
