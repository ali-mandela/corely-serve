"""
Enterprise Multi-Tenant Stores Management System - Security & Encryption
This module provides encryption, hashing, and security utilities for the stores management platform.
"""

import hashlib
import secrets
import base64
import hmac
from typing import Optional, Dict, Any, Tuple, Union
from datetime import datetime, timedelta
import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import jwt

from app._core.config.settings import get_settings
from app._core.utils.constants import AuthConstants, SecurityConstants
from app._core.utils.exceptions import AuthenticationException, ValidationException


class PasswordHasher:
    """Secure password hashing using bcrypt"""

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt with salt"""
        if not password:
            raise ValidationException("Password cannot be empty")

        # Generate salt and hash password
        salt = bcrypt.gensalt(rounds=SecurityConstants.SALT_ROUNDS)
        hashed = bcrypt.hashpw(password.encode("utf-8"), salt)

        return hashed.decode("utf-8")

    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        if not password or not hashed_password:
            return False

        try:
            return bcrypt.checkpw(
                password.encode("utf-8"), hashed_password.encode("utf-8")
            )
        except Exception:
            return False

    @staticmethod
    def check_password_strength(password: str) -> Dict[str, Any]:
        """Check password strength and return analysis"""
        result = {"is_strong": True, "score": 0, "issues": [], "suggestions": []}

        if not password:
            result["is_strong"] = False
            result["issues"].append("Password is empty")
            return result

        # Length check
        if len(password) < AuthConstants.MIN_PASSWORD_LENGTH:
            result["is_strong"] = False
            result["issues"].append(
                f"Password must be at least {AuthConstants.MIN_PASSWORD_LENGTH} characters"
            )
            result["suggestions"].append("Use a longer password")
        else:
            result["score"] += 2

        # Character variety checks
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in '!@#$%^&*(),.?":{}|<>' for c in password)

        if AuthConstants.REQUIRE_UPPERCASE and not has_upper:
            result["is_strong"] = False
            result["issues"].append("Password must contain uppercase letters")
            result["suggestions"].append("Add uppercase letters (A-Z)")
        elif has_upper:
            result["score"] += 1

        if AuthConstants.REQUIRE_LOWERCASE and not has_lower:
            result["is_strong"] = False
            result["issues"].append("Password must contain lowercase letters")
            result["suggestions"].append("Add lowercase letters (a-z)")
        elif has_lower:
            result["score"] += 1

        if AuthConstants.REQUIRE_NUMBERS and not has_digit:
            result["is_strong"] = False
            result["issues"].append("Password must contain numbers")
            result["suggestions"].append("Add numbers (0-9)")
        elif has_digit:
            result["score"] += 1

        if AuthConstants.REQUIRE_SPECIAL_CHARS and not has_special:
            result["is_strong"] = False
            result["issues"].append("Password must contain special characters")
            result["suggestions"].append("Add special characters (!@#$%^&*)")
        elif has_special:
            result["score"] += 1

        # Common password check
        common_passwords = [
            "password",
            "123456",
            "password123",
            "admin",
            "admin123",
            "qwerty",
            "123456789",
            "welcome",
            "password1",
            "abc123",
        ]

        if password.lower() in common_passwords:
            result["is_strong"] = False
            result["issues"].append("Password is too common")
            result["suggestions"].append("Use a unique password")

        # Sequential characters check
        if any(
            password[i : i + 3] in "0123456789abcdefghijklmnopqrstuvwxyz"
            for i in range(len(password) - 2)
        ):
            result["score"] -= 1
            result["suggestions"].append("Avoid sequential characters")

        # Repeated characters check
        if any(
            password[i] == password[i + 1] == password[i + 2]
            for i in range(len(password) - 2)
        ):
            result["score"] -= 1
            result["suggestions"].append("Avoid repeated characters")

        # Final score adjustment
        result["score"] = max(0, min(5, result["score"]))

        return result


class DataEncryption:
    """Data encryption and decryption using Fernet (AES 128)"""

    def __init__(self, encryption_key: Optional[str] = None):
        settings = get_settings()
        self.encryption_key = encryption_key or settings.security.encryption_key

        if not self.encryption_key:
            raise ValueError("Encryption key is required")

        self._cipher = self._get_cipher()

    def _get_cipher(self) -> Fernet:
        """Get Fernet cipher instance"""
        # Convert string key to proper Fernet key
        if len(self.encryption_key) == 32:
            # If key is 32 chars, derive proper key
            key = base64.urlsafe_b64encode(self.encryption_key.encode()[:32])
        else:
            # Assume it's already a proper Fernet key
            key = self.encryption_key.encode()

        try:
            return Fernet(key)
        except Exception:
            # Generate key from provided string
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"stores_management_salt",
                iterations=100000,
                backend=default_backend(),
            )
            key = base64.urlsafe_b64encode(kdf.derive(self.encryption_key.encode()))
            return Fernet(key)

    def encrypt(self, data: str) -> str:
        """Encrypt string data"""
        if not data:
            return ""

        try:
            encrypted_data = self._cipher.encrypt(data.encode("utf-8"))
            return base64.urlsafe_b64encode(encrypted_data).decode("utf-8")
        except Exception as e:
            raise ValidationException(f"Encryption failed: {str(e)}")

    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt string data"""
        if not encrypted_data:
            return ""

        try:
            decoded_data = base64.urlsafe_b64decode(encrypted_data.encode("utf-8"))
            decrypted_data = self._cipher.decrypt(decoded_data)
            return decrypted_data.decode("utf-8")
        except Exception as e:
            raise ValidationException(f"Decryption failed: {str(e)}")

    def encrypt_dict(self, data: Dict[str, Any]) -> str:
        """Encrypt dictionary data"""
        import json

        json_data = json.dumps(data, ensure_ascii=False)
        return self.encrypt(json_data)

    def decrypt_dict(self, encrypted_data: str) -> Dict[str, Any]:
        """Decrypt dictionary data"""
        import json

        json_data = self.decrypt(encrypted_data)
        return json.loads(json_data)


class TokenManager:
    """JWT token management for authentication"""

    def __init__(self):
        settings = get_settings()
        self.secret_key = settings.security.jwt_secret
        self.algorithm = AuthConstants.ALGORITHM
        self.access_token_expire_minutes = AuthConstants.ACCESS_TOKEN_EXPIRE_MINUTES
        self.refresh_token_expire_days = AuthConstants.REFRESH_TOKEN_EXPIRE_DAYS

    def create_access_token(
        self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create JWT access token"""
        to_encode = data.copy()

        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(
                minutes=self.access_token_expire_minutes
            )

        to_encode.update(
            {
                "exp": expire,
                "iat": datetime.utcnow(),
                "type": "access",
                "jti": self._generate_jti(),  # JWT ID for token tracking
            }
        )

        try:
            encoded_jwt = jwt.encode(
                to_encode, self.secret_key, algorithm=self.algorithm
            )
            return encoded_jwt
        except Exception as e:
            raise AuthenticationException(f"Token creation failed: {str(e)}")

    def create_refresh_token(self, data: Dict[str, Any]) -> str:
        """Create JWT refresh token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=self.refresh_token_expire_days)

        to_encode.update(
            {
                "exp": expire,
                "iat": datetime.utcnow(),
                "type": "refresh",
                "jti": self._generate_jti(),
            }
        )

        try:
            encoded_jwt = jwt.encode(
                to_encode, self.secret_key, algorithm=self.algorithm
            )
            return encoded_jwt
        except Exception as e:
            raise AuthenticationException(f"Refresh token creation failed: {str(e)}")

    def verify_token(self, token: str, token_type: str = "access") -> Dict[str, Any]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])

            # Check token type
            if payload.get("type") != token_type:
                raise AuthenticationException(
                    f"Invalid token type. Expected {token_type}"
                )

            return payload
        except jwt.ExpiredSignatureError:
            raise AuthenticationException("Token has expired")
        except jwt.InvalidTokenError as e:
            raise AuthenticationException(f"Invalid token: {str(e)}")

    def get_token_payload(self, token: str) -> Optional[Dict[str, Any]]:
        """Get token payload without verification (for debugging)"""
        try:
            return jwt.decode(token, options={"verify_signature": False})
        except Exception:
            return None

    def _generate_jti(self) -> str:
        """Generate unique JWT ID"""
        return secrets.token_urlsafe(16)

    def create_password_reset_token(self, user_id: str, email: str) -> str:
        """Create password reset token"""
        data = {"user_id": user_id, "email": email, "purpose": "password_reset"}

        expire = datetime.utcnow() + timedelta(
            minutes=SecurityConstants.PASSWORD_RESET_EXPIRE_MINUTES
        )
        data.update(
            {
                "exp": expire,
                "iat": datetime.utcnow(),
                "type": "password_reset",
                "jti": self._generate_jti(),
            }
        )

        try:
            return jwt.encode(data, self.secret_key, algorithm=self.algorithm)
        except Exception as e:
            raise AuthenticationException(
                f"Password reset token creation failed: {str(e)}"
            )

    def verify_password_reset_token(self, token: str) -> Dict[str, Any]:
        """Verify password reset token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])

            if payload.get("type") != "password_reset":
                raise AuthenticationException("Invalid password reset token")

            if payload.get("purpose") != "password_reset":
                raise AuthenticationException("Invalid token purpose")

            return payload
        except jwt.ExpiredSignatureError:
            raise AuthenticationException("Password reset token has expired")
        except jwt.InvalidTokenError as e:
            raise AuthenticationException(f"Invalid password reset token: {str(e)}")


class SecureHash:
    """Secure hashing utilities for data integrity"""

    @staticmethod
    def sha256_hash(data: str) -> str:
        """Create SHA256 hash of data"""
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    @staticmethod
    def hmac_signature(data: str, key: str) -> str:
        """Create HMAC signature for data"""
        return hmac.new(
            key.encode("utf-8"), data.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    @staticmethod
    def verify_hmac_signature(data: str, signature: str, key: str) -> bool:
        """Verify HMAC signature"""
        expected_signature = SecureHash.hmac_signature(data, key)
        return hmac.compare_digest(expected_signature, signature)

    @staticmethod
    def generate_api_key(length: int = 32) -> str:
        """Generate secure API key"""
        return secrets.token_urlsafe(length)

    @staticmethod
    def generate_webhook_secret(length: int = 32) -> str:
        """Generate webhook secret for external integrations"""
        return secrets.token_urlsafe(length)


class SessionSecurity:
    """Session security and management utilities"""

    @staticmethod
    def generate_session_token() -> str:
        """Generate secure session token"""
        return secrets.token_urlsafe(32)

    @staticmethod
    def generate_csrf_token() -> str:
        """Generate CSRF protection token"""
        return secrets.token_urlsafe(32)

    @staticmethod
    def generate_device_fingerprint(user_agent: str, ip_address: str) -> str:
        """Generate device fingerprint for security tracking"""
        data = f"{user_agent}:{ip_address}:{datetime.utcnow().date()}"
        return hashlib.sha256(data.encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def mask_sensitive_data(
        data: str, visible_chars: int = 4, mask_char: str = "*"
    ) -> str:
        """Mask sensitive data for logging/display"""
        if not data or len(data) <= visible_chars:
            return data

        visible_part = data[-visible_chars:]
        masked_part = mask_char * (len(data) - visible_chars)
        return f"{masked_part}{visible_part}"

    @staticmethod
    def generate_otp(length: int = 6) -> str:
        """Generate numeric OTP for 2FA"""
        return "".join(secrets.choice("0123456789") for _ in range(length))

    @staticmethod
    def generate_backup_codes(count: int = 10, length: int = 8) -> list[str]:
        """Generate backup codes for 2FA recovery"""
        codes = []
        for _ in range(count):
            code = "".join(
                secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
                for _ in range(length)
            )
            # Format as XXXX-XXXX
            formatted_code = f"{code[:4]}-{code[4:]}"
            codes.append(formatted_code)
        return codes


class FieldEncryption:
    """Field-level encryption for sensitive database data"""

    def __init__(self, encryption_key: Optional[str] = None):
        self.encryptor = DataEncryption(encryption_key)

    def encrypt_pii(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Encrypt personally identifiable information"""
        pii_fields = [
            "aadhaar",
            "pan",
            "mobile",
            "email",
            "address",
            "bank_account",
            "credit_card",
            "phone",
        ]

        encrypted_data = data.copy()

        for field in pii_fields:
            if field in encrypted_data and encrypted_data[field]:
                encrypted_data[field] = self.encryptor.encrypt(
                    str(encrypted_data[field])
                )
                encrypted_data[f"{field}_encrypted"] = True

        return encrypted_data

    def decrypt_pii(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Decrypt personally identifiable information"""
        decrypted_data = data.copy()

        for key, value in data.items():
            if key.endswith("_encrypted") and value:
                field_name = key.replace("_encrypted", "")
                if field_name in decrypted_data:
                    try:
                        decrypted_data[field_name] = self.encryptor.decrypt(
                            decrypted_data[field_name]
                        )
                        del decrypted_data[key]  # Remove encryption flag
                    except Exception:
                        # If decryption fails, keep original data
                        pass

        return decrypted_data

    def encrypt_financial_data(self, amount: float, reference: str) -> Dict[str, str]:
        """Encrypt financial transaction data"""
        data = {
            "amount": str(amount),
            "reference": reference,
            "timestamp": datetime.utcnow().isoformat(),
        }

        return {
            "encrypted_data": self.encryptor.encrypt_dict(data),
            "checksum": SecureHash.sha256_hash(str(amount) + reference),
        }

    def decrypt_financial_data(
        self, encrypted_data: str, checksum: str
    ) -> Dict[str, Any]:
        """Decrypt financial transaction data with integrity check"""
        data = self.encryptor.decrypt_dict(encrypted_data)

        # Verify integrity
        calculated_checksum = SecureHash.sha256_hash(data["amount"] + data["reference"])
        if not hmac.compare_digest(calculated_checksum, checksum):
            raise ValidationException("Financial data integrity check failed")

        return {
            "amount": float(data["amount"]),
            "reference": data["reference"],
            "timestamp": data["timestamp"],
        }


# Convenience functions for global access
def hash_password(password: str) -> str:
    """Global function to hash password"""
    return PasswordHasher.hash_password(password)


def verify_password(password: str, hashed_password: str) -> bool:
    """Global function to verify password"""
    return PasswordHasher.verify_password(password, hashed_password)


def create_access_token(
    data: Dict[str, Any], expires_delta: Optional[timedelta] = None
) -> str:
    """Global function to create access token"""
    token_manager = TokenManager()
    return token_manager.create_access_token(data, expires_delta)


def verify_token(token: str, token_type: str = "access") -> Dict[str, Any]:
    """Global function to verify token"""
    token_manager = TokenManager()
    return token_manager.verify_token(token, token_type)


def encrypt_data(data: str, encryption_key: Optional[str] = None) -> str:
    """Global function to encrypt data"""
    encryptor = DataEncryption(encryption_key)
    return encryptor.encrypt(data)


def decrypt_data(encrypted_data: str, encryption_key: Optional[str] = None) -> str:
    """Global function to decrypt data"""
    encryptor = DataEncryption(encryption_key)
    return encryptor.decrypt(encrypted_data)


# Export all classes and functions
__all__ = [
    # Classes
    "PasswordHasher",
    "DataEncryption",
    "TokenManager",
    "SecureHash",
    "SessionSecurity",
    "FieldEncryption",
    # Convenience functions
    "hash_password",
    "verify_password",
    "create_access_token",
    "verify_token",
    "encrypt_data",
    "decrypt_data",
]
