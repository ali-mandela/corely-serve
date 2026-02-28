# """
# Enhanced JWT security with key rotation, secure storage, and session management
# """

# import secrets
# import hashlib
# import uuid
# from datetime import datetime, timedelta, timezone
# from typing import Any, Dict, Optional, Union, List, Tuple
# from jose import JWTError, jwt
# from passlib.context import CryptContext
# from passlib.hash import bcrypt
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.backends import default_backend
# import base64
# import re
# import logging

# from app.core.config import settings

# logger = logging.getLogger(__name__)

# # Enhanced password context with stronger settings
# pwd_context = CryptContext(
#     schemes=["bcrypt"],
#     deprecated="auto",
#     bcrypt__rounds=12,  # Higher rounds for better security
#     bcrypt__default_rounds=12,
# )


# class PasswordPolicy:
#     """Enterprise password policy enforcement"""

#     MIN_LENGTH = 12
#     MAX_LENGTH = 128
#     REQUIRE_UPPERCASE = True
#     REQUIRE_LOWERCASE = True
#     REQUIRE_DIGITS = True
#     REQUIRE_SPECIAL = True
#     SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
#     MAX_CONSECUTIVE_CHARS = 3
#     MIN_UNIQUE_CHARS = 8
#     PREVENT_COMMON_PASSWORDS = True

#     @classmethod
#     def validate_password(
#         cls, password: str, username: str = "", email: str = ""
#     ) -> Tuple[bool, List[str]]:
#         """
#         Validate password against enterprise policy

#         Returns:
#             Tuple[bool, List[str]]: (is_valid, list_of_errors)
#         """
#         errors = []

#         # Length check
#         if len(password) < cls.MIN_LENGTH:
#             errors.append(f"Password must be at least {cls.MIN_LENGTH} characters long")
#         if len(password) > cls.MAX_LENGTH:
#             errors.append(f"Password must not exceed {cls.MAX_LENGTH} characters")

#         # Character requirements
#         if cls.REQUIRE_UPPERCASE and not re.search(r"[A-Z]", password):
#             errors.append("Password must contain at least one uppercase letter")

#         if cls.REQUIRE_LOWERCASE and not re.search(r"[a-z]", password):
#             errors.append("Password must contain at least one lowercase letter")

#         if cls.REQUIRE_DIGITS and not re.search(r"\d", password):
#             errors.append("Password must contain at least one digit")

#         if cls.REQUIRE_SPECIAL and not re.search(
#             f"[{re.escape(cls.SPECIAL_CHARS)}]", password
#         ):
#             errors.append(
#                 f"Password must contain at least one special character: {cls.SPECIAL_CHARS}"
#             )

#         # Consecutive characters check
#         consecutive_count = 1
#         for i in range(1, len(password)):
#             if password[i] == password[i - 1]:
#                 consecutive_count += 1
#                 if consecutive_count > cls.MAX_CONSECUTIVE_CHARS:
#                     errors.append(
#                         f"Password cannot have more than {cls.MAX_CONSECUTIVE_CHARS} consecutive identical characters"
#                     )
#                     break
#             else:
#                 consecutive_count = 1

#         # Unique characters check
#         unique_chars = len(set(password))
#         if unique_chars < cls.MIN_UNIQUE_CHARS:
#             errors.append(
#                 f"Password must contain at least {cls.MIN_UNIQUE_CHARS} unique characters"
#             )

#         # Personal information check
#         if username and len(username) > 3 and username.lower() in password.lower():
#             errors.append("Password cannot contain username")

#         if email and len(email) > 3:
#             email_parts = email.split("@")[0]
#             if len(email_parts) > 3 and email_parts.lower() in password.lower():
#                 errors.append("Password cannot contain email address")

#         # Common passwords check
#         if cls.PREVENT_COMMON_PASSWORDS and cls._is_common_password(password):
#             errors.append(
#                 "Password is too common, please choose a more unique password"
#             )

#         return len(errors) == 0, errors

#     @staticmethod
#     def _is_common_password(password: str) -> bool:
#         """Check against common passwords (basic implementation)"""
#         common_passwords = {
#             "password123",
#             "admin123",
#             "welcome123",
#             "qwerty123",
#             "password1",
#             "123456789",
#             "letmein123",
#             "changeme",
#             "password",
#             "123456",
#             "qwerty",
#             "admin",
#         }
#         return password.lower() in common_passwords

#     @classmethod
#     def generate_secure_password(cls, length: int = 16) -> str:
#         """Generate a cryptographically secure password"""
#         if length < cls.MIN_LENGTH:
#             length = cls.MIN_LENGTH

#         # Ensure we have all required character types
#         chars = []
#         if cls.REQUIRE_UPPERCASE:
#             chars.extend("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
#         if cls.REQUIRE_LOWERCASE:
#             chars.extend("abcdefghijklmnopqrstuvwxyz")
#         if cls.REQUIRE_DIGITS:
#             chars.extend("0123456789")
#         if cls.REQUIRE_SPECIAL:
#             chars.extend(cls.SPECIAL_CHARS)

#         # Generate password ensuring all requirements are met
#         password = []

#         # Add at least one character from each required category
#         if cls.REQUIRE_UPPERCASE:
#             password.append(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
#         if cls.REQUIRE_LOWERCASE:
#             password.append(secrets.choice("abcdefghijklmnopqrstuvwxyz"))
#         if cls.REQUIRE_DIGITS:
#             password.append(secrets.choice("0123456789"))
#         if cls.REQUIRE_SPECIAL:
#             password.append(secrets.choice(cls.SPECIAL_CHARS))

#         # Fill remaining length with random characters
#         for _ in range(length - len(password)):
#             password.append(secrets.choice(chars))

#         # Shuffle the password
#         secrets.SystemRandom().shuffle(password)

#         return "".join(password)


# class JWTKeyManager:
#     """Manages JWT signing keys with rotation support"""

#     def __init__(self):
#         self.current_key_id = str(uuid.uuid4())
#         self.keys = {self.current_key_id: self._generate_key()}
#         self.key_created_at = {self.current_key_id: datetime.now(timezone.utc)}

#     def _generate_key(self) -> str:
#         """Generate a cryptographically secure key"""
#         return secrets.token_urlsafe(64)

#     def get_current_key(self) -> Tuple[str, str]:
#         """Get current signing key and its ID"""
#         return self.current_key_id, self.keys[self.current_key_id]

#     def get_key_by_id(self, key_id: str) -> Optional[str]:
#         """Get key by ID for verification"""
#         return self.keys.get(key_id)

#     def rotate_key(self) -> str:
#         """Rotate to a new signing key"""
#         old_key_id = self.current_key_id
#         self.current_key_id = str(uuid.uuid4())
#         self.keys[self.current_key_id] = self._generate_key()
#         self.key_created_at[self.current_key_id] = datetime.now(timezone.utc)

#         logger.info(f"JWT key rotated from {old_key_id} to {self.current_key_id}")
#         return self.current_key_id

#     def cleanup_old_keys(self, retention_hours: int = 24) -> int:
#         """Clean up old keys after retention period"""
#         cutoff_time = datetime.now(timezone.utc) - timedelta(hours=retention_hours)
#         removed_count = 0

#         keys_to_remove = []
#         for key_id, created_at in self.key_created_at.items():
#             if key_id != self.current_key_id and created_at < cutoff_time:
#                 keys_to_remove.append(key_id)

#         for key_id in keys_to_remove:
#             del self.keys[key_id]
#             del self.key_created_at[key_id]
#             removed_count += 1

#         if removed_count > 0:
#             logger.info(f"Cleaned up {removed_count} old JWT keys")

#         return removed_count

#     def should_rotate(self, max_age_hours: int = 24) -> bool:
#         """Check if current key should be rotated"""
#         current_age = datetime.now(timezone.utc) - self.key_created_at[self.current_key_id]
#         return current_age > timedelta(hours=max_age_hours)


# class SessionManager:
#     """Manages user sessions with revocation support"""

#     def __init__(self):
#         self.active_sessions: Dict[str, Dict[str, Any]] = {}
#         self.user_sessions: Dict[str, List[str]] = {}  # user_id -> [session_ids]

#     def create_session(
#         self,
#         user_id: str,
#         ip_address: str,
#         user_agent: str,
#         tenant_id: Optional[str] = None,
#     ) -> str:
#         """Create a new session"""
#         session_id = str(uuid.uuid4())
#         session_data = {
#             "user_id": user_id,
#             "tenant_id": tenant_id,
#             "ip_address": ip_address,
#             "user_agent": user_agent,
#             "created_at": datetime.now(timezone.utc),
#             "last_accessed": datetime.now(timezone.utc),
#             "is_active": True,
#         }

#         self.active_sessions[session_id] = session_data

#         # Track user sessions
#         if user_id not in self.user_sessions:
#             self.user_sessions[user_id] = []
#         self.user_sessions[user_id].append(session_id)

#         return session_id

#     def validate_session(self, session_id: str, user_id: str, ip_address: str) -> bool:
#         """Validate an active session"""
#         session = self.active_sessions.get(session_id)
#         if not session or not session["is_active"]:
#             return False

#         # Verify user and IP (optional strict IP checking)
#         if session["user_id"] != user_id:
#             return False

#         # Update last accessed time
#         session["last_accessed"] = datetime.now(timezone.utc)
#         return True

#     def revoke_session(self, session_id: str) -> bool:
#         """Revoke a specific session"""
#         if session_id in self.active_sessions:
#             session = self.active_sessions[session_id]
#             session["is_active"] = False

#             # Remove from user sessions
#             user_id = session["user_id"]
#             if (
#                 user_id in self.user_sessions
#                 and session_id in self.user_sessions[user_id]
#             ):
#                 self.user_sessions[user_id].remove(session_id)

#             return True
#         return False

#     def revoke_user_sessions(self, user_id: str) -> int:
#         """Revoke all sessions for a user"""
#         if user_id not in self.user_sessions:
#             return 0

#         revoked_count = 0
#         for session_id in self.user_sessions[user_id].copy():
#             if self.revoke_session(session_id):
#                 revoked_count += 1

#         return revoked_count

#     def cleanup_expired_sessions(self, max_age_hours: int = 24) -> int:
#         """Clean up expired sessions"""
#         cutoff_time = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
#         expired_sessions = []

#         for session_id, session in self.active_sessions.items():
#             if session["last_accessed"] < cutoff_time:
#                 expired_sessions.append(session_id)

#         for session_id in expired_sessions:
#             self.revoke_session(session_id)

#         return len(expired_sessions)


# class EnhancedJWTSecurity:
#     """Enhanced JWT security with key rotation and session management"""

#     def __init__(self):
#         self.key_manager = JWTKeyManager()
#         self.session_manager = SessionManager()

#     def create_access_token(
#         self,
#         subject: Union[str, Dict[str, Any]],
#         expires_delta: Optional[timedelta] = None,
#         ip_address: str = "unknown",
#         user_agent: str = "unknown",
#         include_session: bool = True,
#     ) -> Dict[str, Any]:
#         """Create enhanced JWT access token with session management"""

#         if expires_delta:
#             expire = datetime.now(timezone.utc) + expires_delta
#         else:
#             expire = datetime.now(timezone.utc) + timedelta(
#                 minutes=settings.access_token_expire_minutes
#             )

#         # Build payload
#         if isinstance(subject, str):
#             payload = {"sub": subject}
#             user_id = subject
#             tenant_id = None
#         else:
#             payload = subject.copy()
#             user_id = payload.get("sub") or payload.get("user_id")
#             tenant_id = payload.get("organization_id") or payload.get("tenant_id")

#         # Add standard claims
#         payload.update(
#             {
#                 "exp": expire,
#                 "iat": datetime.now(timezone.utc),
#                 "jti": str(uuid.uuid4()),  # JWT ID for tracking
#             }
#         )

#         # Create session if requested
#         session_id = None
#         if include_session and user_id:
#             session_id = self.session_manager.create_session(
#                 user_id=user_id,
#                 ip_address=ip_address,
#                 user_agent=user_agent,
#                 tenant_id=tenant_id,
#             )
#             payload["session_id"] = session_id

#         # Get current signing key
#         key_id, signing_key = self.key_manager.get_current_key()
#         payload["kid"] = key_id  # Key ID for verification

#         # Sign token
#         token = jwt.encode(
#             payload, signing_key, algorithm=settings.algorithm, headers={"kid": key_id}
#         )

#         return {
#             "access_token": token,
#             "token_type": "bearer",
#             "expires_in": (
#                 int(expires_delta.total_seconds())
#                 if expires_delta
#                 else settings.access_token_expire_minutes * 60
#             ),
#             "session_id": session_id,
#             "created_at": datetime.now(timezone.utc).isoformat(),
#         }

#     def verify_token(
#         self, token: str, verify_session: bool = True, ip_address: str = "unknown"
#     ) -> Optional[Dict[str, Any]]:
#         """Verify JWT token with enhanced security checks"""

#         try:
#             # Decode header to get key ID
#             header = jwt.get_unverified_header(token)
#             key_id = header.get("kid")

#             if not key_id:
#                 logger.warning("JWT token missing key ID")
#                 return None

#             # Get signing key
#             signing_key = self.key_manager.get_key_by_id(key_id)
#             if not signing_key:
#                 logger.warning(f"Unknown JWT key ID: {key_id}")
#                 return None

#             # Verify token
#             payload = jwt.decode(token, signing_key, algorithms=[settings.algorithm])

#             # Verify session if requested
#             if verify_session and "session_id" in payload:
#                 session_id = payload["session_id"]
#                 user_id = payload.get("sub") or payload.get("user_id")

#                 if not self.session_manager.validate_session(
#                     session_id, user_id, ip_address
#                 ):
#                     logger.warning(f"Invalid session: {session_id}")
#                     return None

#             # Remove sensitive claims from returned payload
#             result = payload.copy()
#             result.pop("exp", None)
#             result.pop("iat", None)

#             return result

#         except JWTError as e:
#             logger.warning(f"JWT verification failed: {e}")
#             return None
#         except Exception as e:
#             logger.error(f"Token verification error: {e}")
#             return None

#     def revoke_token(self, token: str) -> bool:
#         """Revoke a specific token by session"""
#         try:
#             # Get session ID from token (without verification)
#             payload = jwt.get_unverified_claims(token)
#             session_id = payload.get("session_id")

#             if session_id:
#                 return self.session_manager.revoke_session(session_id)

#             return False
#         except Exception as e:
#             logger.error(f"Error revoking token: {e}")
#             return False

#     def revoke_user_tokens(self, user_id: str) -> int:
#         """Revoke all tokens for a user"""
#         return self.session_manager.revoke_user_sessions(user_id)

#     def rotate_keys(self) -> str:
#         """Rotate JWT signing keys"""
#         return self.key_manager.rotate_key()

#     def cleanup_expired_data(self) -> Dict[str, int]:
#         """Clean up expired sessions and keys"""
#         expired_sessions = self.session_manager.cleanup_expired_sessions()
#         expired_keys = self.key_manager.cleanup_old_keys()

#         return {"expired_sessions": expired_sessions, "expired_keys": expired_keys}


# # Enhanced password functions
# def validate_password_strength(
#     password: str, username: str = "", email: str = ""
# ) -> Tuple[bool, List[str]]:
#     """Validate password against enterprise policy"""
#     return PasswordPolicy.validate_password(password, username, email)


# def generate_secure_password(length: int = 16) -> str:
#     """Generate a secure password"""
#     return PasswordPolicy.generate_secure_password(length)


# def hash_password(password: str) -> str:
#     """Hash password with enhanced security"""
#     return pwd_context.hash(password)


# def verify_password(plain_password: str, hashed_password: str) -> bool:
#     """Verify password against hash"""
#     return pwd_context.verify(plain_password, hashed_password)


# # Global enhanced JWT security instance
# enhanced_jwt = EnhancedJWTSecurity()


# # Backward compatibility functions
# def create_access_token(
#     subject: Union[str, Dict[str, Any]], expires_delta: Optional[timedelta] = None
# ) -> str:
#     """Create access token (backward compatibility)"""
#     result = enhanced_jwt.create_access_token(subject, expires_delta)
#     return result["access_token"]


# def verify_token(token: str) -> Optional[Dict[str, Any]]:
#     """Verify token (backward compatibility)"""
#     return enhanced_jwt.verify_token(token)


# def get_password_hash(password: str) -> str:
#     """Get password hash (backward compatibility)"""
#     return hash_password(password)
