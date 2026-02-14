"""
User authentication service with Google & GitHub OAuth and JWT tokens
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional, Any

import httpx
from fastapi import HTTPException, status
from jose import JWTError, jwt
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

from .config import settings
from .supabase_utils import get_rest_base, get_rest_headers
from .user_models import GoogleAuthRequest, GitHubAuthRequest, UserResponse, TokenResponse

# JWT settings
SECRET_KEY = settings.api_key or secrets.token_urlsafe(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days
GOOGLE_CLIENT_ID = settings.google_client_id if hasattr(settings, 'google_client_id') else None
GITHUB_CLIENT_ID = settings.github_client_id if hasattr(settings, 'github_client_id') else None
GITHUB_CLIENT_SECRET = settings.github_client_secret if hasattr(settings, 'github_client_secret') else None


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and validate a JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


def verify_google_token(credential: str) -> Optional[Dict[str, Any]]:
    """Verify Google ID token and extract user info"""
    try:
        # Verify the token with Google
        idinfo = id_token.verify_oauth2_token(
            credential, 
            google_requests.Request(), 
            GOOGLE_CLIENT_ID
        )
        
        # Token is valid, return user info
        return {
            "email": idinfo.get("email"),
            "name": idinfo.get("name"),
            "picture": idinfo.get("picture"),
            "sub": idinfo.get("sub")  # Google user ID
        }
    except Exception as e:
        print(f"Google token verification failed: {e}")
        return None


async def verify_github_token(access_token: str) -> Optional[Dict[str, Any]]:
    """Verify GitHub access token and fetch user info"""
    try:
        async with httpx.AsyncClient() as client:
            # Get user info from GitHub API
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github.v3+json"
            }
            
            # Get basic user info
            user_resp = await client.get("https://api.github.com/user", headers=headers)
            if user_resp.status_code != 200:
                return None
            
            user_data = user_resp.json()
            
            # Get user emails
            emails_resp = await client.get("https://api.github.com/user/emails", headers=headers)
            primary_email = user_data.get("email")
            
            if emails_resp.status_code == 200:
                emails = emails_resp.json()
                for email_obj in emails:
                    if email_obj.get("primary") and email_obj.get("verified"):
                        primary_email = email_obj.get("email")
                        break
            
            if not primary_email:
                return None
            
            return {
                "email": primary_email,
                "name": user_data.get("name") or user_data.get("login"),
                "picture": user_data.get("avatar_url"),
                "sub": str(user_data.get("id")),
                "provider": "github"
            }
    except Exception as e:
        print(f"GitHub token verification failed: {e}")
        return None


async def _create_or_update_user(oauth_user: Dict[str, Any], provider: str) -> Dict[str, Any]:
    """Shared helper to create or update user from OAuth data"""
    rest_base = get_rest_base()
    headers = get_rest_headers()
    
    if not rest_base or not headers:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service unavailable"
        )
    
    async with httpx.AsyncClient() as client:
        # Check if user exists
        user_url = f"{rest_base}/users?email=eq.{oauth_user['email']}&select=*"
        resp = await client.get(user_url, headers=headers)
        
        current_time = datetime.utcnow().isoformat()
        
        if resp.status_code == 200 and resp.json():
            # User exists, update their info
            user = resp.json()[0]
            
            # Check if user is suspended
            if user.get("is_suspended", False):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Account suspended. Please contact support."
                )
            
            # Update user info and last_active
            update_data = {
                "full_name": oauth_user.get("name"),
                "picture": oauth_user.get("picture"),
                "last_active": current_time
            }
            
            # Update provider-specific ID
            if provider == "google":
                update_data["google_id"] = oauth_user.get("sub")
            elif provider == "github":
                update_data["github_id"] = oauth_user.get("sub")
            
            update_url = f"{rest_base}/users?id=eq.{user['id']}"
            await client.patch(update_url, headers=headers, json=update_data)
            
            # Fetch updated user
            resp = await client.get(user_url, headers=headers)
            user = resp.json()[0]
        else:
            # Create new user
            user_id = hashlib.sha256(oauth_user['email'].encode()).hexdigest()[:16]
            
            new_user = {
                "id": user_id,
                "email": oauth_user['email'],
                "full_name": oauth_user.get('name'),
                "picture": oauth_user.get('picture'),
                "provider": provider,
                "role": "user",
                "is_suspended": False,
                "created_at": current_time,
                "last_active": current_time,
                "scan_count": 0
            }
            
            # Add provider-specific ID
            if provider == "google":
                new_user["google_id"] = oauth_user.get('sub')
            elif provider == "github":
                new_user["github_id"] = oauth_user.get('sub')
            
            insert_resp = await client.post(
                f"{rest_base}/users",
                headers=headers,
                json=new_user
            )
            
            if insert_resp.status_code not in (200, 201):
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to create user"
                )
            
            created_user = insert_resp.json()
            user = created_user[0] if isinstance(created_user, list) else created_user
        
        return user


async def authenticate_with_google(auth_request: GoogleAuthRequest) -> TokenResponse:
    """Authenticate user with Google OAuth and return JWT token"""
    # Verify Google token
    google_user = verify_google_token(auth_request.credential)
    
    if not google_user or not google_user.get("email"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Google credential"
        )
    
    # Create or update user
    user = await _create_or_update_user(google_user, "google")
    
    # Create access token
    access_token = create_access_token(data={"sub": user["id"], "email": user["email"]})
    
    user_response = UserResponse(
        id=user["id"],
        email=user["email"],
        full_name=user.get("full_name"),
        picture=user.get("picture"),
        created_at=user["created_at"],
        role=user.get("role", "user"),
        provider=user.get("provider", "google"),
        is_suspended=user.get("is_suspended", False),
        last_active=user.get("last_active"),
        scan_count=user.get("scan_count", 0)
    )
    
    return TokenResponse(access_token=access_token, user=user_response)


async def authenticate_with_github(auth_request: GitHubAuthRequest) -> TokenResponse:
    """Authenticate user with GitHub OAuth and return JWT token"""
    # Verify GitHub token
    github_user = await verify_github_token(auth_request.access_token)
    
    if not github_user or not github_user.get("email"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid GitHub access token"
        )
    
    # Create or update user
    user = await _create_or_update_user(github_user, "github")
    
    # Create access token
    access_token = create_access_token(data={"sub": user["id"], "email": user["email"]})
    
    user_response = UserResponse(
        id=user["id"],
        email=user["email"],
        full_name=user.get("full_name"),
        picture=user.get("picture"),
        created_at=user["created_at"],
        role=user.get("role", "user"),
        provider=user.get("provider", "github"),
        is_suspended=user.get("is_suspended", False),
        last_active=user.get("last_active"),
        scan_count=user.get("scan_count", 0)
    )
    
    return TokenResponse(access_token=access_token, user=user_response)


async def get_user_by_id(user_id: str) -> Optional[UserResponse]:
    """Get user by ID"""
    rest_base = get_rest_base()
    headers = get_rest_headers()
    
    if not rest_base or not headers:
        return None
    
    async with httpx.AsyncClient() as client:
        user_url = f"{rest_base}/users?id=eq.{user_id}&select=*"
        resp = await client.get(user_url, headers=headers)
        
        if resp.status_code != 200 or not resp.json():
            return None
        
        user = resp.json()[0]
        
        # Check if user is suspended
        if user.get("is_suspended", False):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account suspended. Please contact support."
            )
        
        return UserResponse(
            id=user["id"],
            email=user["email"],
            full_name=user.get("full_name"),
            picture=user.get("picture"),
            created_at=user["created_at"],
            role=user.get("role", "user"),
            provider=user.get("provider"),
            is_suspended=user.get("is_suspended", False),
            last_active=user.get("last_active"),
            scan_count=user.get("scan_count", 0)
        )


async def increment_scan_count(user_id: str) -> None:
    """Increment user's scan count"""
    rest_base = get_rest_base()
    headers = get_rest_headers()
    
    if not rest_base or not headers:
        return
    
    async with httpx.AsyncClient() as client:
        # Get current count
        user_url = f"{rest_base}/users?id=eq.{user_id}&select=scan_count"
        resp = await client.get(user_url, headers=headers)
        
        if resp.status_code == 200 and resp.json():
            current_count = resp.json()[0].get("scan_count", 0)
            
            # Update count
            update_url = f"{rest_base}/users?id=eq.{user_id}"
            await client.patch(
                update_url,
                headers=headers,
                json={"scan_count": current_count + 1}
            )
