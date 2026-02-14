"""
anxextor - Updated User Service for 5NF Normalized Schema
Supports multiple OAuth providers per user
"""

from typing import Optional, Dict, Any, List
from datetime import datetime
import logging
from supabase import Client

logger = logging.getLogger(__name__)


class UserOAuthService:
    """Service for managing user OAuth providers (5NF normalized)"""
    
    def __init__(self, supabase_client: Client):
        self.db = supabase_client
    
    def link_provider(
        self,
        user_id: str,
        provider: str,
        provider_user_id: str,
        set_as_primary: bool = False
    ) -> Dict[str, Any]:
        """
        Link an OAuth provider to a user account.
        
        Args:
            user_id: anxextor user ID
            provider: OAuth provider name ('google', 'github', etc.)
            provider_user_id: User ID from the OAuth provider
            set_as_primary: Whether to set this as the primary login method
        
        Returns:
            Dictionary with linked provider data
        """
        try:
            # Use the stored procedure for linking
            result = self.db.rpc(
                'link_oauth_provider',
                {
                    'p_user_id': user_id,
                    'p_provider': provider,
                    'p_provider_user_id': provider_user_id,
                    'p_set_as_primary': set_as_primary
                }
            ).execute()
            
            logger.info(f"Linked {provider} provider to user {user_id}")
            return {"success": True, "provider": provider}
            
        except Exception as e:
            logger.error(f"Failed to link {provider} for user {user_id}: {e}")
            raise
    
    def unlink_provider(self, user_id: str, provider: str) -> Dict[str, Any]:
        """
        Unlink an OAuth provider from a user account.
        Will fail if it's the only provider.
        
        Args:
            user_id: anxextor user ID
            provider: OAuth provider name to unlink
        
        Returns:
            Dictionary with success status
        """
        try:
            result = self.db.rpc(
                'unlink_oauth_provider',
                {
                    'p_user_id': user_id,
                    'p_provider': provider
                }
            ).execute()
            
            logger.info(f"Unlinked {provider} provider from user {user_id}")
            return {"success": True, "provider": provider}
            
        except Exception as e:
            logger.error(f"Failed to unlink {provider} for user {user_id}: {e}")
            raise
    
    def get_user_providers(self, user_id: str) -> List[Dict[str, Any]]:
        """
        Get all OAuth providers linked to a user.
        
        Args:
            user_id: anxextor user ID
        
        Returns:
            List of provider dictionaries
        """
        try:
            result = self.db.table('user_oauth_providers')\
                .select('*')\
                .eq('user_id', user_id)\
                .order('is_primary', desc=True)\
                .order('last_used_at', desc=True)\
                .execute()
            
            return result.data
            
        except Exception as e:
            logger.error(f"Failed to get providers for user {user_id}: {e}")
            raise
    
    def get_primary_provider(self, user_id: str) -> Optional[str]:
        """
        Get user's primary OAuth provider.
        
        Args:
            user_id: anxextor user ID
        
        Returns:
            Provider name or None
        """
        try:
            result = self.db.rpc(
                'get_primary_oauth_provider',
                {'p_user_id': user_id}
            ).execute()
            
            return result.data if result.data else None
            
        except Exception as e:
            logger.error(f"Failed to get primary provider for user {user_id}: {e}")
            return None
    
    def update_last_used(self, user_id: str, provider: str) -> None:
        """
        Update the last_used_at timestamp for a provider.
        Call this on successful login.
        
        Args:
            user_id: anxextor user ID
            provider: OAuth provider name
        """
        try:
            self.db.table('user_oauth_providers')\
                .update({'last_used_at': datetime.utcnow().isoformat()})\
                .eq('user_id', user_id)\
                .eq('provider', provider)\
                .execute()
            
            logger.debug(f"Updated last_used_at for {provider} - user {user_id}")
            
        except Exception as e:
            logger.error(f"Failed to update last_used for {provider}: {e}")
    
    def find_user_by_provider(
        self,
        provider: str,
        provider_user_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Find a user by their OAuth provider ID.
        
        Args:
            provider: OAuth provider name
            provider_user_id: User ID from the OAuth provider
        
        Returns:
            User data or None
        """
        try:
            # Query oauth_providers table then join to users
            result = self.db.table('user_oauth_providers')\
                .select('user_id, users(*)')\
                .eq('provider', provider)\
                .eq('provider_user_id', provider_user_id)\
                .single()\
                .execute()
            
            if result.data:
                return result.data.get('users')
            return None
            
        except Exception as e:
            logger.warning(f"User not found for {provider} ID {provider_user_id}: {e}")
            return None


class UserService:
    """Main user service (updated for 5NF schema)"""
    
    def __init__(self, supabase_client: Client):
        self.db = supabase_client
        self.oauth = UserOAuthService(supabase_client)
    
    def create_or_update_user_from_oauth(
        self,
        email: str,
        provider: str,
        provider_user_id: str,
        full_name: Optional[str] = None,
        picture: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create or update a user from OAuth login.
        New 5NF implementation supporting multiple providers.
        
        Args:
            email: User's email address
            provider: OAuth provider ('google', 'github')
            provider_user_id: User ID from OAuth provider
            full_name: User's full name
            picture: Profile picture URL
        
        Returns:
            User data dictionary
        """
        try:
            # Check if user exists by email
            existing = self.db.table('users')\
                .select('*')\
                .eq('email', email)\
                .limit(1)\
                .execute()
            
            if existing.data:
                # User exists - update and link provider
                user = existing.data[0]
                user_id = user['id']
                
                # Update user profile
                self.db.table('users')\
                    .update({
                        'full_name': full_name or user.get('full_name'),
                        'picture': picture or user.get('picture'),
                        'last_active': datetime.utcnow().isoformat()
                    })\
                    .eq('id', user_id)\
                    .execute()
                
                # Link the OAuth provider (if not already linked)
                try:
                    self.oauth.link_provider(
                        user_id,
                        provider,
                        provider_user_id,
                        set_as_primary=False  # Don't change primary on existing users
                    )
                except Exception:
                    # Provider may already be linked - that's okay
                    pass
                
                # Update last_used for this provider
                self.oauth.update_last_used(user_id, provider)
                
                logger.info(f"Updated existing user {user_id} with {provider} OAuth")
                return self.get_user_with_providers(user_id)
            
            else:
                # New user - create account
                import hashlib
                user_id = hashlib.sha256(email.encode()).hexdigest()[:16]
                
                # Create user record
                user_data = {
                    'id': user_id,
                    'email': email,
                    'full_name': full_name,
                    'picture': picture,
                    'role': 'user',
                    'is_suspended': False,
                    'scan_count': 0,
                    'created_at': datetime.utcnow().isoformat(),
                    'last_active': datetime.utcnow().isoformat()
                }
                
                result = self.db.table('users')\
                    .insert(user_data)\
                    .execute()
                
                # Link the OAuth provider as primary
                self.oauth.link_provider(
                    user_id,
                    provider,
                    provider_user_id,
                    set_as_primary=True  # First provider is always primary
                )
                
                logger.info(f"Created new user {user_id} with {provider} OAuth")
                return self.get_user_with_providers(user_id)
            
        except Exception as e:
            logger.error(f"Failed to create/update user from OAuth: {e}")
            raise
    
    def get_user_with_providers(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get user data with all linked OAuth providers.
        
        Args:
            user_id: anxextor user ID
        
        Returns:
            User data with providers array
        """
        try:
            # Use the backward compatibility view
            result = self.db.table('users_with_oauth')\
                .select('*')\
                .eq('id', user_id)\
                .single()\
                .execute()
            
            if result.data:
                # Add provider details
                providers = self.oauth.get_user_providers(user_id)
                result.data['oauth_providers'] = providers
                result.data['provider_count'] = len(providers)
            
            return result.data
            
        except Exception as e:
            logger.error(f"Failed to get user {user_id}: {e}")
            return None
    
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user by email address"""
        try:
            result = self.db.table('users')\
                .select('*')\
                .eq('email', email)\
                .single()\
                .execute()
            
            if result.data:
                return self.get_user_with_providers(result.data['id'])
            return None
            
        except Exception as e:
            logger.warning(f"User not found for email {email}: {e}")
            return None
    
    def authenticate_oauth_user(
        self,
        provider: str,
        provider_user_id: str,
        email: str,
        full_name: Optional[str] = None,
        picture: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Authenticate or register user via OAuth.
        Wrapper for backward compatibility.
        
        Args:
            provider: OAuth provider name
            provider_user_id: User ID from OAuth provider
            email: User email
            full_name: User's full name
            picture: Profile picture URL
        
        Returns:
            User data dictionary
        """
        # First try to find by provider ID
        user = self.oauth.find_user_by_provider(provider, provider_user_id)
        
        if user:
            # Update last active
            self.db.table('users')\
                .update({'last_active': datetime.utcnow().isoformat()})\
                .eq('id', user['id'])\
                .execute()
            
            self.oauth.update_last_used(user['id'], provider)
            return self.get_user_with_providers(user['id'])
        
        # User not found by provider ID - create or link
        return self.create_or_update_user_from_oauth(
            email, provider, provider_user_id, full_name, picture
        )
    
    def update_role(self, user_id: str, new_role: str) -> Dict[str, Any]:
        """Update user's role"""
        valid_roles = ['user', 'manager', 'admin', 'super_admin']
        if new_role not in valid_roles:
            raise ValueError(f"Invalid role. Must be one of {valid_roles}")
        
        try:
            result = self.db.table('users')\
                .update({'role': new_role})\
                .eq('id', user_id)\
                .execute()
            
            logger.info(f"Updated role for user {user_id} to {new_role}")
            return result.data[0] if result.data else None
            
        except Exception as e:
            logger.error(f"Failed to update role for user {user_id}: {e}")
            raise
    
    def suspend_user(self, user_id: str, suspend: bool = True) -> Dict[str, Any]:
        """Suspend or unsuspend a user"""
        try:
            result = self.db.table('users')\
                .update({'is_suspended': suspend})\
                .eq('id', user_id)\
                .execute()
            
            action = "suspended" if suspend else "unsuspended"
            logger.info(f"User {user_id} {action}")
            return result.data[0] if result.data else None
            
        except Exception as e:
            logger.error(f"Failed to suspend user {user_id}: {e}")
            raise
    
    def increment_scan_count(self, user_id: str) -> None:
        """Increment user's scan counter"""
        try:
            self.db.table('users')\
                .update({
                    'scan_count': self.db.rpc('increment', {'x': 1}),
                    'last_active': datetime.utcnow().isoformat()
                })\
                .eq('id', user_id)\
                .execute()
            
            logger.debug(f"Incremented scan count for user {user_id}")
            
        except Exception as e:
            logger.error(f"Failed to increment scan count for user {user_id}: {e}")
    
    def get_all_users(
        self,
        role: Optional[str] = None,
        include_suspended: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Get all users with optional filters.
        
        Args:
            role: Filter by role (optional)
            include_suspended: Include suspended users
        
        Returns:
            List of user dictionaries
        """
        try:
            query = self.db.table('users_with_oauth').select('*')
            
            if role:
                query = query.eq('role', role)
            
            if not include_suspended:
                query = query.eq('is_suspended', False)
            
            result = query.order('created_at', desc=True).execute()
            return result.data
            
        except Exception as e:
            logger.error(f"Failed to get users: {e}")
            raise


# Example usage:
"""
from app.config import Config
from supabase import create_client

# Initialize
config = Config()
supabase = create_client(config.SUPABASE_URL, config.SUPABASE_SERVICE_KEY)
user_service = UserService(supabase)

# Authenticate Google user
user = user_service.authenticate_oauth_user(
    provider='google',
    provider_user_id='1234567890',
    email='user@example.com',
    full_name='John Doe',
    picture='https://example.com/photo.jpg'
)

# Get user with all providers
user_data = user_service.get_user_with_providers(user['id'])
print(f"User has {user_data['provider_count']} OAuth providers linked")

# Link GitHub to existing user
user_service.oauth.link_provider(
    user_id=user['id'],
    provider='github',
    provider_user_id='github_user_123',
    set_as_primary=False
)

# List all user's providers
providers = user_service.oauth.get_user_providers(user['id'])
for p in providers:
    print(f"{p['provider']}: Primary={p['is_primary']}, Last used={p['last_used_at']}")

# Unlink a provider
user_service.oauth.unlink_provider(user['id'], 'github')
"""
