"""
User authentication models for anxextor - Google OAuth
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field


class GoogleAuthRequest(BaseModel):
    """Google OAuth token from frontend"""
    credential: str = Field(..., description="Google JWT credential token")


class UserResponse(BaseModel):
    """User data response (safe for client)"""
    id: str
    email: str
    full_name: Optional[str] = None
    picture: Optional[str] = None
    created_at: datetime
    is_premium: bool = False
    scan_count: int = 0


class TokenResponse(BaseModel):
    """Authentication token response"""
    access_token: str
    token_type: str = "bearer"
    user: UserResponse
