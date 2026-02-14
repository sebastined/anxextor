-- Migration: Add GitHub OAuth and User Management Fields
-- Date: 2024
-- Description: Adds support for GitHub OAuth, roles, suspension, and activity tracking

-- Create users table if it doesn't exist
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(16) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    full_name VARCHAR(255),
    picture TEXT,
    google_id VARCHAR(255) UNIQUE,
    provider VARCHAR(20) DEFAULT 'google',
    github_id VARCHAR(255),
    role VARCHAR(20) DEFAULT 'user',
    is_suspended BOOLEAN DEFAULT FALSE,
    scan_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    last_active TIMESTAMP
);

-- Add new columns if they don't exist (for existing tables)
DO $$
BEGIN
    -- Add provider column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'users' AND column_name = 'provider'
    ) THEN
        ALTER TABLE users ADD COLUMN provider VARCHAR(20) DEFAULT 'google';
    END IF;

    -- Add github_id column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'users' AND column_name = 'github_id'
    ) THEN
        ALTER TABLE users ADD COLUMN github_id VARCHAR(255);
    END IF;

    -- Add role column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'users' AND column_name = 'role'
    ) THEN
        ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT 'user';
    END IF;

    -- Add is_suspended column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'users' AND column_name = 'is_suspended'
    ) THEN
        ALTER TABLE users ADD COLUMN is_suspended BOOLEAN DEFAULT FALSE;
    END IF;

    -- Add last_active column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'users' AND column_name = 'last_active'
    ) THEN
        ALTER TABLE users ADD COLUMN last_active TIMESTAMP;
    END IF;
END $$;

-- Update existing users to have default role
UPDATE users 
SET role = 'user' 
WHERE role IS NULL;

-- Remove is_premium column (replaced by role field)
-- Note: Uncomment this after migrating any premium users to 'premium' role
-- ALTER TABLE users DROP COLUMN IF EXISTS is_premium;

-- Add indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_provider ON users(provider);
CREATE INDEX IF NOT EXISTS idx_users_github_id ON users(github_id);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_is_suspended ON users(is_suspended);
CREATE INDEX IF NOT EXISTS idx_users_last_active ON users(last_active);

-- Add check constraint for valid roles (skip if already exists)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_user_role'
    ) THEN
        ALTER TABLE users ADD CONSTRAINT chk_user_role 
        CHECK (role IN ('user', 'manager', 'admin', 'super_admin'));
    END IF;
END $$;

-- Add check constraint for valid providers (skip if already exists)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_user_provider'
    ) THEN
        ALTER TABLE users ADD CONSTRAINT chk_user_provider 
        CHECK (provider IN ('google', 'github'));
    END IF;
END $$;

-- Optional: Create view for active users
CREATE OR REPLACE VIEW active_users AS
SELECT *
FROM users
WHERE is_suspended = FALSE;

-- Optional: Create view for recently active users (last 30 days)
CREATE OR REPLACE VIEW recently_active_users AS
SELECT *
FROM users
WHERE is_suspended = FALSE 
  AND last_active >= NOW() - INTERVAL '30 days';
