"""
Enterprise Multi-Tenant Stores Management System - Input Validation & Sanitization
This module provides comprehensive input validation and sanitization for security.
"""

import re
import html
import urllib.parse
from typing import Any, Dict, List, Optional, Union, Tuple
from datetime import datetime, date
from decimal import Decimal, InvalidOperation
import bleach
from email_validator import validate_email, EmailNotValidError

from app._core.utils.constants import (
    ValidationConstants,
    ProductConstants,
    SecurityConstants,
)
from app._core.utils.exceptions import (
    ValidationException,
    InvalidEmailException,
    InvalidPhoneException,
)
from app._core.utils.validators import (
    ValidationResult,
    IndianDocumentValidators,
    ContactValidators,
    BusinessValidators,
    DateTimeValidators,
)


class InputSanitizer:
    """Input sanitization utilities for XSS and injection prevention"""

    # Allowed HTML tags for rich text (very restrictive)
    ALLOWED_TAGS = ["p", "br", "strong", "em", "u", "ol", "ul", "li"]
    ALLOWED_ATTRIBUTES = {}

    @staticmethod
    def sanitize_string(
        input_str: str, max_length: Optional[int] = None, allow_html: bool = False
    ) -> str:
        """Sanitize string input to prevent XSS and injection attacks"""
        if not isinstance(input_str, str):
            input_str = str(input_str) if input_str is not None else ""

        # Remove null bytes and control characters
        sanitized = input_str.replace("\x00", "").replace("\r\n", "\n")

        # Remove or escape control characters except newline and tab
        sanitized = "".join(
            char for char in sanitized if ord(char) >= 32 or char in ["\n", "\t"]
        )

        if allow_html:
            # Clean HTML using bleach
            sanitized = bleach.clean(
                sanitized,
                tags=InputSanitizer.ALLOWED_TAGS,
                attributes=InputSanitizer.ALLOWED_ATTRIBUTES,
                strip=True,
            )
        else:
            # Escape HTML entities
            sanitized = html.escape(sanitized)

        # Trim whitespace
        sanitized = sanitized.strip()

        # Apply length limit
        if max_length and len(sanitized) > max_length:
            sanitized = sanitized[:max_length]

        return sanitized

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename to prevent path traversal attacks"""
        if not filename:
            return ""

        # Remove path separators and dangerous characters
        dangerous_chars = ["/", "\\", "..", "~", ":", "*", "?", '"', "<", ">", "|"]
        sanitized = filename

        for char in dangerous_chars:
            sanitized = sanitized.replace(char, "_")

        # Remove leading/trailing dots and spaces
        sanitized = sanitized.strip(". ")

        # Ensure filename is not empty and has reasonable length
        if not sanitized:
            sanitized = "file"

        if len(sanitized) > 255:
            sanitized = sanitized[:255]

        return sanitized

    @staticmethod
    def sanitize_url(url: str) -> str:
        """Sanitize URL to prevent malicious redirects"""
        if not url:
            return ""

        try:
            # Parse and validate URL
            parsed = urllib.parse.urlparse(url)

            # Only allow http/https schemes
            if parsed.scheme not in ["http", "https"]:
                return ""

            # Rebuild URL with safe components
            safe_url = urllib.parse.urlunparse(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment,
                )
            )

            return safe_url
        except Exception:
            return ""

    @staticmethod
    def sanitize_json_input(
        data: Dict[str, Any], max_depth: int = 10
    ) -> Dict[str, Any]:
        """Sanitize JSON input recursively"""
        if max_depth <= 0:
            return {}

        if not isinstance(data, dict):
            return {}

        sanitized = {}

        for key, value in data.items():
            # Sanitize key
            clean_key = InputSanitizer.sanitize_string(str(key), 100)
            if not clean_key:
                continue

            # Sanitize value based on type
            if isinstance(value, str):
                sanitized[clean_key] = InputSanitizer.sanitize_string(value, 10000)
            elif isinstance(value, dict):
                sanitized[clean_key] = InputSanitizer.sanitize_json_input(
                    value, max_depth - 1
                )
            elif isinstance(value, list):
                sanitized[clean_key] = [
                    (
                        InputSanitizer.sanitize_string(str(item), 1000)
                        if isinstance(item, str)
                        else item
                    )
                    for item in value[:100]  # Limit array size
                ]
            elif isinstance(value, (int, float, bool)) or value is None:
                sanitized[clean_key] = value
            else:
                sanitized[clean_key] = InputSanitizer.sanitize_string(str(value), 1000)

        return sanitized


class SQLInjectionPrevention:
    """SQL injection prevention utilities"""

    # Common SQL injection patterns
    SQL_INJECTION_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
        r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
        r"(\b(OR|AND)\s+['\"][^'\"]*['\"])",
        r"(--|#|/\*|\*/)",
        r"(\bSCRIPT\b)",
        r"(\bEXEC\b)",
        r"(\bSP_\w+)",
        r"(\bXP_\w+)",
    ]

    @staticmethod
    def detect_sql_injection(input_str: str) -> bool:
        """Detect potential SQL injection attempts"""
        if not input_str:
            return False

        # Convert to uppercase for pattern matching
        upper_input = input_str.upper()

        for pattern in SQLInjectionPrevention.SQL_INJECTION_PATTERNS:
            if re.search(pattern, upper_input, re.IGNORECASE):
                return True

        return False

    @staticmethod
    def sanitize_query_param(param: str) -> str:
        """Sanitize query parameter to prevent SQL injection"""
        if SQLInjectionPrevention.detect_sql_injection(param):
            raise ValidationException("Potential SQL injection detected")

        return InputSanitizer.sanitize_string(param)


class BusinessDataValidator:
    """Business-specific data validation for stores management"""

    @staticmethod
    def validate_store_data(data: Dict[str, Any]) -> ValidationResult:
        """Validate store creation/update data"""
        result = ValidationResult()

        # Required fields
        required_fields = ["name", "store_type", "address", "pincode", "manager_mobile"]
        for field in required_fields:
            if not data.get(field):
                result.add_error(f"{field} is required", field)

        if not result.is_valid:
            return result

        # Sanitize inputs
        data["name"] = InputSanitizer.sanitize_string(data["name"], 200)
        data["address"] = InputSanitizer.sanitize_string(data["address"], 500)

        # Validate specific fields
        if data.get("store_type") not in [
            "retail",
            "outlet",
            "flagship",
            "pop_up",
            "online",
        ]:
            result.add_error("Invalid store type", "store_type")

        # Validate PIN code
        pin_result = IndianDocumentValidators.indian_pincode(data["pincode"])
        if not pin_result.is_valid:
            result.merge(pin_result)

        # Validate mobile number
        mobile_result = ContactValidators.indian_mobile(data["manager_mobile"])
        if not mobile_result.is_valid:
            result.merge(mobile_result)

        # Validate optional fields
        if data.get("email"):
            email_result = ContactValidators.email(data["email"])
            if not email_result.is_valid:
                result.merge(email_result)

        if data.get("gstin"):
            gstin_result = IndianDocumentValidators.gstin(data["gstin"])
            if not gstin_result.is_valid:
                result.merge(gstin_result)

        return result

    @staticmethod
    def validate_product_data(data: Dict[str, Any]) -> ValidationResult:
        """Validate product creation/update data"""
        result = ValidationResult()

        # Required fields
        required_fields = ["name", "sku", "category", "price"]
        for field in required_fields:
            if not data.get(field):
                result.add_error(f"{field} is required", field)

        if not result.is_valid:
            return result

        # Sanitize inputs
        data["name"] = InputSanitizer.sanitize_string(data["name"], 200)
        data["description"] = InputSanitizer.sanitize_string(
            data.get("description", ""), 1000, allow_html=True
        )

        # Validate SKU
        sku_result = BusinessValidators.sku(data["sku"])
        if not sku_result.is_valid:
            result.merge(sku_result)

        # Validate price
        price_result = BusinessValidators.price(data["price"])
        if not price_result.is_valid:
            result.merge(price_result)

        # Validate barcode if provided
        if data.get("barcode"):
            barcode_result = BusinessValidators.barcode(
                data["barcode"], data.get("barcode_type", "UPC")
            )
            if not barcode_result.is_valid:
                result.merge(barcode_result)

        # Validate inventory quantity
        if "quantity" in data:
            qty_result = BusinessValidators.inventory_quantity(data["quantity"])
            if not qty_result.is_valid:
                result.merge(qty_result)

        return result

    @staticmethod
    def validate_employee_data(data: Dict[str, Any]) -> ValidationResult:
        """Validate employee creation/update data"""
        result = ValidationResult()

        # Required fields
        required_fields = ["first_name", "last_name", "email", "mobile", "role"]
        for field in required_fields:
            if not data.get(field):
                result.add_error(f"{field} is required", field)

        if not result.is_valid:
            return result

        # Sanitize inputs
        data["first_name"] = InputSanitizer.sanitize_string(data["first_name"], 50)
        data["last_name"] = InputSanitizer.sanitize_string(data["last_name"], 50)

        # Validate email
        email_result = ContactValidators.email(data["email"])
        if not email_result.is_valid:
            result.merge(email_result)

        # Validate mobile
        mobile_result = ContactValidators.indian_mobile(data["mobile"])
        if not mobile_result.is_valid:
            result.merge(mobile_result)

        # Validate role
        valid_roles = [
            "store_manager",
            "assistant_manager",
            "shift_supervisor",
            "cashier",
            "sales_associate",
            "inventory_clerk",
        ]
        if data["role"] not in valid_roles:
            result.add_error("Invalid employee role", "role")

        # Validate optional fields
        if data.get("pan"):
            pan_result = IndianDocumentValidators.pan(data["pan"])
            if not pan_result.is_valid:
                result.merge(pan_result)

        if data.get("aadhaar"):
            aadhaar_result = IndianDocumentValidators.aadhaar(data["aadhaar"])
            if not aadhaar_result.is_valid:
                result.merge(aadhaar_result)

        if data.get("birth_date"):
            age_result = DateTimeValidators.age_validation(data["birth_date"], 18, 70)
            if not age_result.is_valid:
                result.merge(age_result)

        return result

    @staticmethod
    def validate_customer_data(data: Dict[str, Any]) -> ValidationResult:
        """Validate customer creation/update data"""
        result = ValidationResult()

        # Required fields
        required_fields = ["name", "mobile"]
        for field in required_fields:
            if not data.get(field):
                result.add_error(f"{field} is required", field)

        if not result.is_valid:
            return result

        # Sanitize inputs
        data["name"] = InputSanitizer.sanitize_string(data["name"], 100)

        # Validate mobile
        mobile_result = ContactValidators.indian_mobile(data["mobile"])
        if not mobile_result.is_valid:
            result.merge(mobile_result)

        # Validate optional email
        if data.get("email"):
            email_result = ContactValidators.email(data["email"])
            if not email_result.is_valid:
                result.merge(email_result)

        # Validate optional address
        if data.get("address"):
            data["address"] = InputSanitizer.sanitize_string(data["address"], 500)

        if data.get("pincode"):
            pin_result = IndianDocumentValidators.indian_pincode(data["pincode"])
            if not pin_result.is_valid:
                result.merge(pin_result)

        return result


class FileUploadValidator:
    """File upload validation and security"""

    # Allowed file extensions
    ALLOWED_EXTENSIONS = {
        "images": {".jpg", ".jpeg", ".png", ".gif", ".webp"},
        "documents": {".pdf", ".doc", ".docx", ".txt"},
        "spreadsheets": {".xls", ".xlsx", ".csv"},
        "archives": {".zip", ".rar"},
    }

    # Maximum file sizes (in bytes)
    MAX_FILE_SIZES = {
        "images": 5 * 1024 * 1024,  # 5MB
        "documents": 10 * 1024 * 1024,  # 10MB
        "spreadsheets": 25 * 1024 * 1024,  # 25MB
        "archives": 50 * 1024 * 1024,  # 50MB
    }

    @staticmethod
    def validate_file_upload(
        file_data: bytes, filename: str, file_type: str = "documents"
    ) -> ValidationResult:
        """Validate uploaded file"""
        result = ValidationResult()

        if not file_data:
            result.add_error("File data is empty", "file")
            return result

        if not filename:
            result.add_error("Filename is required", "filename")
            return result

        # Sanitize filename
        safe_filename = InputSanitizer.sanitize_filename(filename)
        if not safe_filename:
            result.add_error("Invalid filename", "filename")
            return result

        # Check file extension
        file_ext = "." + filename.split(".")[-1].lower() if "." in filename else ""
        allowed_extensions = FileUploadValidator.ALLOWED_EXTENSIONS.get(
            file_type, set()
        )

        if file_ext not in allowed_extensions:
            result.add_error(
                f"File type not allowed. Allowed: {', '.join(allowed_extensions)}",
                "file_type",
            )

        # Check file size
        file_size = len(file_data)
        max_size = FileUploadValidator.MAX_FILE_SIZES.get(file_type, 10 * 1024 * 1024)

        if file_size > max_size:
            result.add_error(
                f"File too large. Maximum size: {max_size // (1024 * 1024)}MB",
                "file_size",
            )

        # Check for malicious content
        if FileUploadValidator._contains_malicious_content(file_data, file_ext):
            result.add_error(
                "File contains potentially malicious content", "file_content"
            )

        return result

    @staticmethod
    def _contains_malicious_content(file_data: bytes, file_ext: str) -> bool:
        """Check for malicious content in uploaded files"""
        # Check for embedded scripts in text files
        if file_ext in [".txt", ".csv"]:
            content = file_data.decode("utf-8", errors="ignore").lower()
            malicious_patterns = [
                "<script",
                "javascript:",
                "vbscript:",
                "onload=",
                "onerror=",
            ]

            for pattern in malicious_patterns:
                if pattern in content:
                    return True

        # Check for executable file signatures
        executable_signatures = [
            b"MZ",  # Windows executable
            b"\x7fELF",  # Linux executable
            b"\xca\xfe\xba\xbe",  # Java class file
        ]

        for signature in executable_signatures:
            if file_data.startswith(signature):
                return True

        return False


class APIInputValidator:
    """API input validation for REST endpoints"""

    @staticmethod
    def validate_pagination_params(page: int, page_size: int) -> ValidationResult:
        """Validate pagination parameters"""
        result = ValidationResult()

        if page < 1:
            result.add_error("Page must be greater than 0", "page")

        if page_size < 1:
            result.add_error("Page size must be greater than 0", "page_size")
        elif page_size > ValidationConstants.MAX_PAGE_SIZE:
            result.add_error(
                f"Page size cannot exceed {ValidationConstants.MAX_PAGE_SIZE}",
                "page_size",
            )

        return result

    @staticmethod
    def validate_search_params(
        search_query: str, filters: Dict[str, Any]
    ) -> ValidationResult:
        """Validate search and filter parameters"""
        result = ValidationResult()

        if search_query:
            # Sanitize search query
            clean_query = InputSanitizer.sanitize_string(search_query, 200)

            # Check for SQL injection
            if SQLInjectionPrevention.detect_sql_injection(clean_query):
                result.add_error("Invalid search query", "search")

            # Minimum length check
            if len(clean_query.strip()) < 2:
                result.add_error("Search query must be at least 2 characters", "search")

        if filters:
            # Validate filter structure
            sanitized_filters = InputSanitizer.sanitize_json_input(filters, max_depth=3)

            # Check for reasonable number of filters
            if len(sanitized_filters) > 20:
                result.add_error("Too many filters applied", "filters")

        return result

    @staticmethod
    def validate_bulk_operation(
        data: List[Dict[str, Any]], max_items: int = 1000
    ) -> ValidationResult:
        """Validate bulk operation data"""
        result = ValidationResult()

        if not data:
            result.add_error("Bulk data cannot be empty", "data")
            return result

        if len(data) > max_items:
            result.add_error(f"Bulk operation limited to {max_items} items", "data")

        # Validate each item in the bulk data
        for i, item in enumerate(data[:100]):  # Check first 100 items
            if not isinstance(item, dict):
                result.add_error(f"Item {i+1} must be an object", f"data[{i}]")
                continue

            # Sanitize item data
            sanitized_item = InputSanitizer.sanitize_json_input(item)
            data[i] = sanitized_item

        return result


class TenantDataValidator:
    """Multi-tenant data validation"""

    @staticmethod
    def validate_tenant_isolation(
        data: Dict[str, Any], expected_tenant_id: str
    ) -> ValidationResult:
        """Validate that data belongs to the correct tenant"""
        result = ValidationResult()

        # Check if tenant_id is present and matches
        if "tenant_id" not in data:
            result.add_error("Tenant ID is required", "tenant_id")
        elif data["tenant_id"] != expected_tenant_id:
            result.add_error("Tenant ID mismatch", "tenant_id")

        return result

    @staticmethod
    def validate_cross_tenant_reference(
        reference_data: Dict[str, Any], current_tenant_id: str
    ) -> ValidationResult:
        """Validate cross-tenant references are not allowed"""
        result = ValidationResult()

        # Check for references to other tenants
        for key, value in reference_data.items():
            if key.endswith("_id") and isinstance(value, str):
                # If it looks like a tenant-prefixed ID
                if "_" in value and not value.startswith(current_tenant_id):
                    result.add_error(f"Cross-tenant reference not allowed: {key}", key)

        return result


# Convenience functions for common validations
def sanitize_user_input(data: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize user input data"""
    return InputSanitizer.sanitize_json_input(data)


def validate_indian_mobile(mobile: str) -> bool:
    """Validate Indian mobile number format"""
    result = ContactValidators.indian_mobile(mobile)
    return result.is_valid


def validate_indian_email(email: str) -> bool:
    """Validate email address"""
    result = ContactValidators.email(email)
    return result.is_valid


def validate_gstin(gstin: str) -> bool:
    """Validate Indian GSTIN"""
    result = IndianDocumentValidators.gstin(gstin)
    return result.is_valid


def detect_malicious_input(input_str: str) -> bool:
    """Detect potentially malicious input"""
    if SQLInjectionPrevention.detect_sql_injection(input_str):
        return True

    # Check for XSS patterns
    xss_patterns = [
        r"<script.*?>.*?</script>",
        r"javascript:",
        r"vbscript:",
        r"on\w+\s*=",
        r"<iframe.*?>",
        r"<object.*?>",
        r"<embed.*?>",
    ]

    for pattern in xss_patterns:
        if re.search(pattern, input_str, re.IGNORECASE):
            return True

    return False


# Export all classes and functions
__all__ = [
    # Classes
    "InputSanitizer",
    "SQLInjectionPrevention",
    "BusinessDataValidator",
    "FileUploadValidator",
    "APIInputValidator",
    "TenantDataValidator",
    # Convenience functions
    "sanitize_user_input",
    "validate_indian_mobile",
    "validate_indian_email",
    "validate_gstin",
    "detect_malicious_input",
]
