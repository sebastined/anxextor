# Google OAuth Setup Guide

## Overview
The anxextor security scanner now supports Google Sign-In for authentication. This guide explains how to configure Google OAuth.

## Features Requiring Authentication
- **PDF Export**: Generate professional security reports
- **Scan History**: Track all your security scans
- **User Profile**: View scan statistics and account info

## Setup Instructions

### 1. Create Google OAuth Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Navigate to **APIs & Services** → **Credentials**
4. Click **Create Credentials** → **OAuth client ID**
5. Configure consent screen if prompted:
   - User Type: External
   - App name: anxextor
   - Support email: your email
   - Authorized domains: your domain
6. Create OAuth Client ID:
   - Application type: **Web application**
   - Name: anxextor-client
   - Authorized JavaScript origins:
     - `http://localhost:8000` (development)
     - `https://yourdomain.com` (production)
   - Authorized redirect URIs:
     - `http://localhost:8000/auth.html` (development)
     - `https://yourdomain.com/auth.html` (production)
7. Copy the **Client ID** (NOT the Client Secret)

### 2. Configure Environment Variables

Add the Google Client ID to your `.env` file:

```bash
# Google OAuth Configuration
GOOGLE_CLIENT_ID=your-client-id-here.apps.googleusercontent.com
```

### 3. Set up Supabase Database

Create a `users` table in your Supabase database:

```sql
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  full_name TEXT,
  picture TEXT,
  google_id TEXT UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  is_premium BOOLEAN DEFAULT FALSE,
  scan_count INTEGER DEFAULT 0
);

-- Add indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_google_id ON users(google_id);
```

### 4. Deploy and Test

1. **Local Testing**:
   ```bash
   cd backend
   python -m uvicorn app.main:app --reload --port 8000
   ```

2. **Production Deployment**:
   - Set `GOOGLE_CLIENT_ID` environment variable on Render.com
   - Ensure database schema is created
   - Deploy updated code

### 5. Using Authentication

#### For Users:
1. Click **🔐 Login** button on home page
2. Click **Sign in with Google**
3. Authorize anxextor to access your email and profile
4. You'll be redirected back with authentication complete

#### For Developers:
- Access token is stored in `localStorage.access_token`
- User profile is stored in `localStorage.user`
- Protected endpoints require `Authorization: Bearer <token>` header

## API Endpoints

### Public Endpoints
- `POST /api/auth/login` - Login with Google credential
- `POST /api/auth/register` - Same as login (auto-creates user)
- `GET /api/config` - Get client config including Google Client ID

### Protected Endpoints (Require Auth)
- `GET /api/auth/me` - Get current user profile
- `POST /api/auth/logout` - Logout (client-side token removal)
- `POST /api/export-pdf` - Export scan results to PDF

## Frontend Pages

- `/auth.html` - Google Sign-In page
- `/profile.html` - User profile with stats
- `/` - Main scanner (with login/profile navigation)

## Security Considerations

1. **Client ID is public** - It's safe to include in frontend code
2. **JWT tokens expire** - 7-day expiration, users must re-login
3. **HTTPS required** - Google OAuth requires HTTPS in production
4. **Token validation** - Backend verifies Google tokens with Google API
5. **No passwords stored** - Google handles all authentication

## Troubleshooting

### "Google Sign-In not configured"
- Check `GOOGLE_CLIENT_ID` is set in environment
- Verify the Client ID is correct
- Restart the backend server

### "Authentication failed"
- Verify authorized domains in Google Console
- Check redirect URIs match exactly
- Ensure HTTPS is used in production

### "Database service unavailable"
- Verify `ANXEXTOR_SUPABASE_URL` is set
- Verify `ANXEXTOR_SUPABASE_SERVICE_KEY` is set
- Check Supabase database is accessible

### Token expired
- Users need to login again
- Token is valid for 7 days
- Stored in browser localStorage

## Development Notes

### Backend Architecture
- `user_service.py` - Google token verification, JWT creation
- `user_models.py` - Pydantic models for auth requests/responses
- `main.py` - Auth endpoints and middleware

### Frontend Architecture
- `auth.html` - Google Sign-In integration
- `profile.html` - User profile dashboard
- `app.js` - Auth UI, token management, protected API calls

## Environment Variables Reference

```bash
# Required for Google OAuth
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com

# Required for database
ANXEXTOR_SUPABASE_URL=https://your-project.supabase.co
ANXEXTOR_SUPABASE_SERVICE_KEY=your-service-key

# Optional JWT customization (defaults to ANXEXTOR_API_KEY)
# SECRET_KEY=custom-jwt-secret
```

## Next Steps

- [ ] Configure Google Client ID
- [ ] Set up Supabase users table
- [ ] Test authentication flow
- [ ] Deploy to production
- [ ] Monitor user signups
