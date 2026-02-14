"""
User authentication models for anxextor - OAuth (Google & GitHub)
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field


class GoogleAuthRequest(BaseModel):
    """Google OAuth token from frontend"""
    credential: str = Field(..., description="Google JWT credential token")


class GitHubAuthRequest(BaseModel):
    """GitHub OAuth token from frontend"""
    access_token: str = Field(..., description="GitHub access token")


class UserResponse(BaseModel):
    """User data response (safe for client)"""
    id: str
    email: str
    full_name: Optional[str] = None
    picture: Optional[str] = None
    provider: Optional[str] = None  # 'google' or 'github'
    created_at: datetime
    role: str = "user"  # user, manager, admin, super_admin
    is_suspended: bool = False
    scan_count: int = 0
    last_active: Optional[datetime] = None


class TokenResponse(BaseModel):
    """Authentication token response"""
    access_token: str
    token_type: str = "bearer"
    user: UserResponse
