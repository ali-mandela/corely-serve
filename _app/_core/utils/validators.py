"""
Enterprise Multi-Tenant Stores Management System Validators
This module contains comprehensive validation functions for the India-based stores management platform.
"""

import re
from datetime import datetime, date, time
from typing import Any, Dict, List, Optional, Union, Tuple
from decimal import Decimal, InvalidOperation
from enum import Enum

from app._core.utils.constants import (
    # ValidationConstants,
    ProductConstants,
    TenantConstants,
    StoreConstants,
    EmployeeConstants,
    CustomerConstants,
    # RegexPatterns,
    AuthConstants,
)
from app._core.utils.exceptions import ValidationException, RequiredFieldException


class ValidationResult:
    """Result of validation operation"""

    def __init__(
        self,
        is_valid: bool = True,
        errors: Optional[List[str]] = None,
        field_errors: Optional[Dict[str, List[str]]] = None,
    ):
        self.is_valid = is_valid
        self.errors = errors or []
        self.field_errors = field_errors or {}

    def add_error(self, error: str, field: str = None):
        """Add validation error"""
        self.is_valid = False
        if field:
            if field not in self.field_errors:
                self.field_errors[field] = []
            self.field_errors[field].append(error)
        else:
            self.errors.append(error)

    def merge(self, other: "ValidationResult"):
        """Merge another validation result"""
        if not other.is_valid:
            self.is_valid = False
        self.errors.extend(other.errors)
        for field, field_errors in other.field_errors.items():
            if field not in self.field_errors:
                self.field_errors[field] = []
            self.field_errors[field].extend(field_errors)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses"""
        return {
            "is_valid": self.is_valid,
            "errors": self.errors,
            "field_errors": self.field_errors,
        }


# ================== BASIC FIELD VALIDATORS ==================


class BasicValidators:
    """Basic field validation functions"""

    @staticmethod
    def required(value: Any, field_name: str = "field") -> ValidationResult:
        """Validate required field"""
        result = ValidationResult()
        if value is None or (isinstance(value, str) and value.strip() == ""):
            result.add_error(f"{field_name} is required", field_name)
        return result

    @staticmethod
    def string_length(
        value: str,
        min_length: int = 0,
        max_length: int = None,
        field_name: str = "field",
    ) -> ValidationResult:
        """Validate string length"""
        result = ValidationResult()
        if not isinstance(value, str):
            result.add_error(f"{field_name} must be a string", field_name)
            return result

        length = len(value.strip())
        if length < min_length:
            result.add_error(
                f"{field_name} must be at least {min_length} characters long",
                field_name,
            )
        if max_length and length > max_length:
            result.add_error(
                f"{field_name} must not exceed {max_length} characters", field_name
            )

        return result

    @staticmethod
    def numeric_range(
        value: Union[int, float, Decimal],
        min_value: Union[int, float, Decimal] = None,
        max_value: Union[int, float, Decimal] = None,
        field_name: str = "field",
    ) -> ValidationResult:
        """Validate numeric range"""
        result = ValidationResult()
        try:
            num_value = float(value)
        except (ValueError, TypeError):
            result.add_error(f"{field_name} must be a valid number", field_name)
            return result

        if min_value is not None and num_value < min_value:
            result.add_error(f"{field_name} must be at least {min_value}", field_name)
        if max_value is not None and num_value > max_value:
            result.add_error(f"{field_name} must not exceed {max_value}", field_name)

        return result

    @staticmethod
    def regex_pattern(
        value: str, pattern: str, field_name: str = "field", error_message: str = None
    ) -> ValidationResult:
        """Validate against regex pattern"""
        result = ValidationResult()
        if not isinstance(value, str):
            result.add_error(f"{field_name} must be a string", field_name)
            return result

        if not re.match(pattern, value):
            message = error_message or f"{field_name} format is invalid"
            result.add_error(message, field_name)

        return result

    @staticmethod
    def choice_validator(
        value: Any, choices: List[Any], field_name: str = "field"
    ) -> ValidationResult:
        """Validate value is in allowed choices"""
        result = ValidationResult()
        if value not in choices:
            result.add_error(
                f"{field_name} must be one of: {', '.join(map(str, choices))}",
                field_name,
            )
        return result


# ================== INDIAN DOCUMENT VALIDATORS ==================


class IndianDocumentValidators:
    """Validators for Indian business documents"""

    @staticmethod
    def gstin(gstin: str) -> ValidationResult:
        """Validate Indian GST Identification Number"""
        result = ValidationResult()

        if not gstin:
            result.add_error("GSTIN is required", "gstin")
            return result

        gstin = gstin.strip().upper()

        # Length check
        if len(gstin) != 15:
            result.add_error("GSTIN must be 15 characters long", "gstin")
            return result

        # Format check: 2 digits state code + 10 chars PAN + 1 char entity + 1 char Z + 1 check digit
        gstin_pattern = (
            r"^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}[Z]{1}[0-9A-Z]{1}$"
        )
        if not re.match(gstin_pattern, gstin):
            result.add_error("Invalid GSTIN format", "gstin")
            return result

        # State code validation (01-37)
        state_code = int(gstin[:2])
        if not (1 <= state_code <= 37):
            result.add_error("Invalid state code in GSTIN", "gstin")

        return result

    @staticmethod
    def pan(pan: str) -> ValidationResult:
        """Validate Indian PAN (Permanent Account Number)"""
        result = ValidationResult()

        if not pan:
            result.add_error("PAN is required", "pan")
            return result

        pan = pan.strip().upper()

        # Length and format check
        if len(pan) != 10:
            result.add_error("PAN must be 10 characters long", "pan")
            return result

        # PAN format: 5 letters + 4 digits + 1 letter
        pan_pattern = r"^[A-Z]{5}[0-9]{4}[A-Z]{1}$"
        if not re.match(pan_pattern, pan):
            result.add_error("Invalid PAN format (AAAAA9999A)", "pan")

        return result

    @staticmethod
    def aadhaar(aadhaar: str) -> ValidationResult:
        """Validate Indian Aadhaar number"""
        result = ValidationResult()

        if not aadhaar:
            result.add_error("Aadhaar number is required", "aadhaar")
            return result

        # Remove spaces and hyphens
        cleaned = re.sub(r"[\s-]", "", aadhaar.strip())

        # Length check
        if len(cleaned) != 12:
            result.add_error("Aadhaar must be 12 digits long", "aadhaar")
            return result

        # Should be all digits
        if not cleaned.isdigit():
            result.add_error("Aadhaar must contain only digits", "aadhaar")
            return result

        # First digit should not be 0 or 1
        if cleaned[0] in ["0", "1"]:
            result.add_error("Aadhaar cannot start with 0 or 1", "aadhaar")

        return result

    @staticmethod
    def ifsc(ifsc: str) -> ValidationResult:
        """Validate Indian IFSC (Indian Financial System Code)"""
        result = ValidationResult()

        if not ifsc:
            result.add_error("IFSC code is required", "ifsc")
            return result

        ifsc = ifsc.strip().upper()

        # Length check
        if len(ifsc) != 11:
            result.add_error("IFSC code must be 11 characters long", "ifsc")
            return result

        # Format check: 4 letters + 0 + 6 alphanumeric
        ifsc_pattern = r"^[A-Z]{4}0[A-Z0-9]{6}$"
        if not re.match(ifsc_pattern, ifsc):
            result.add_error("Invalid IFSC format (AAAA0BBBBBB)", "ifsc")

        return result

    @staticmethod
    def indian_pincode(pincode: str) -> ValidationResult:
        """Validate Indian PIN code"""
        result = ValidationResult()

        if not pincode:
            result.add_error("PIN code is required", "pincode")
            return result

        pincode = pincode.strip()

        # Should be 6 digits
        if not re.match(r"^\d{6}$", pincode):
            result.add_error("PIN code must be 6 digits", "pincode")
            return result

        # First digit should not be 0
        if pincode[0] == "0":
            result.add_error("PIN code cannot start with 0", "pincode")

        return result


# ================== CONTACT INFORMATION VALIDATORS ==================


class ContactValidators:
    """Validators for contact information"""

    @staticmethod
    def email(email: str) -> ValidationResult:
        """Validate email address"""
        result = ValidationResult()

        if not email:
            result.add_error("Email is required", "email")
            return result

        email = email.strip().lower()

        # Length check
        if len(email) > ValidationConstants.MAX_EMAIL_LENGTH:
            result.add_error(
                f"Email must not exceed {ValidationConstants.MAX_EMAIL_LENGTH} characters",
                "email",
            )
            return result

        # Format check
        if not re.match(ValidationConstants.EMAIL_REGEX, email):
            result.add_error("Invalid email format", "email")

        return result

    @staticmethod
    def indian_mobile(mobile: str) -> ValidationResult:
        """Validate Indian mobile number"""
        result = ValidationResult()

        if not mobile:
            result.add_error("Mobile number is required", "mobile")
            return result

        # Remove all non-digit characters except +
        cleaned = re.sub(r"[^\d+]", "", mobile.strip())

        # Indian mobile patterns
        indian_patterns = [
            r"^\+91[6-9]\d{9}$",  # +91 followed by 10 digits starting with 6-9
            r"^91[6-9]\d{9}$",  # 91 followed by 10 digits starting with 6-9
            r"^[6-9]\d{9}$",  # 10 digits starting with 6-9
        ]

        if not any(re.match(pattern, cleaned) for pattern in indian_patterns):
            result.add_error("Invalid Indian mobile number format", "mobile")

        return result

    @staticmethod
    def landline(landline: str, include_std: bool = True) -> ValidationResult:
        """Validate Indian landline number"""
        result = ValidationResult()

        if not landline:
            return result  # Landline is optional

        cleaned = re.sub(r"[^\d+\-\s]", "", landline.strip())
        digits_only = re.sub(r"[^\d]", "", cleaned)

        if include_std:
            # With STD code: 2-4 digits STD + 6-8 digits number
            if not re.match(r"^\d{8,12}$", digits_only):
                result.add_error("Invalid landline format with STD code", "landline")
        else:
            # Without STD: 6-8 digits
            if not re.match(r"^\d{6,8}$", digits_only):
                result.add_error("Invalid landline format", "landline")

        return result


# ================== BUSINESS VALIDATORS ==================


class BusinessValidators:
    """Validators for business-specific fields"""

    @staticmethod
    def sku(sku: str) -> ValidationResult:
        """Validate product SKU"""
        result = ValidationResult()

        if not sku:
            result.add_error("SKU is required", "sku")
            return result

        sku = sku.strip().upper()

        # Check format: XXX-XXX-XXX
        if not re.match(ProductConstants.SKU_PATTERN, sku):
            result.add_error("Invalid SKU format (XXX-XXX-XXX)", "sku")

        return result

    @staticmethod
    def barcode(barcode: str, barcode_type: str = "UPC") -> ValidationResult:
        """Validate product barcode"""
        result = ValidationResult()

        if not barcode:
            result.add_error("Barcode is required", "barcode")
            return result

        patterns = ProductConstants.BARCODE_PATTERNS
        if barcode_type not in patterns:
            result.add_error(
                f"Unsupported barcode type: {barcode_type}", "barcode_type"
            )
            return result

        if not re.match(patterns[barcode_type], barcode.strip()):
            result.add_error(f"Invalid {barcode_type} barcode format", "barcode")

        return result

    @staticmethod
    def store_hours(open_time: str, close_time: str) -> ValidationResult:
        """Validate store operating hours"""
        result = ValidationResult()

        try:
            open_dt = datetime.strptime(open_time, "%H:%M")
            close_dt = datetime.strptime(close_time, "%H:%M")

            # Handle overnight hours
            if close_dt < open_dt:
                close_dt = close_dt.replace(day=open_dt.day + 1)

            # Store should be open for at least 1 hour and max 24 hours
            duration = close_dt - open_dt
            if duration.total_seconds() < 3600:  # Less than 1 hour
                result.add_error("Store must be open for at least 1 hour", "hours")
            elif duration.total_seconds() > 86400:  # More than 24 hours
                result.add_error("Store cannot be open for more than 24 hours", "hours")

        except ValueError:
            result.add_error("Invalid time format (use HH:MM)", "hours")

        return result

    @staticmethod
    def price(
        price: Union[str, int, float, Decimal], min_price: Decimal = Decimal("0.01")
    ) -> ValidationResult:
        """Validate product price"""
        result = ValidationResult()

        try:
            price_decimal = Decimal(str(price))
        except (ValueError, InvalidOperation):
            result.add_error("Invalid price format", "price")
            return result

        if price_decimal < min_price:
            result.add_error(f"Price must be at least ₹{min_price}", "price")

        # Check for reasonable maximum (10 crores)
        if price_decimal > Decimal("100000000"):
            result.add_error("Price exceeds maximum allowed value", "price")

        return result

    @staticmethod
    def inventory_quantity(quantity: Union[str, int]) -> ValidationResult:
        """Validate inventory quantity"""
        result = ValidationResult()

        try:
            qty = int(quantity)
        except (ValueError, TypeError):
            result.add_error("Quantity must be a valid integer", "quantity")
            return result

        if qty < 0:
            result.add_error("Quantity cannot be negative", "quantity")

        # Check for reasonable maximum
        if qty > 1000000:
            result.add_error("Quantity exceeds maximum allowed value", "quantity")

        return result


# ================== EMPLOYEE VALIDATORS ==================


class EmployeeValidators:
    """Validators for employee-related fields"""

    @staticmethod
    def employee_id(emp_id: str, store_code: str = None) -> ValidationResult:
        """Validate employee ID format"""
        result = ValidationResult()

        if not emp_id:
            result.add_error("Employee ID is required", "employee_id")
            return result

        emp_id = emp_id.strip().upper()

        # Format: STORE-YYMM-001
        if not re.match(r"^[A-Z0-9]{3,6}-\d{4}-\d{3}$", emp_id):
            result.add_error(
                "Invalid employee ID format (STORE-YYMM-001)", "employee_id"
            )
            return result

        # If store code provided, check if it matches
        if store_code:
            emp_store_code = emp_id.split("-")[0]
            if emp_store_code != store_code.upper():
                result.add_error(
                    f"Employee ID must start with store code {store_code}",
                    "employee_id",
                )

        return result

    @staticmethod
    def salary(salary: Union[str, int, float, Decimal]) -> ValidationResult:
        """Validate employee salary"""
        result = ValidationResult()

        try:
            salary_decimal = Decimal(str(salary))
        except (ValueError, InvalidOperation):
            result.add_error("Invalid salary format", "salary")
            return result

        # Minimum wage check (approximate Indian minimum wage)
        if salary_decimal < Decimal("15000"):
            result.add_error("Salary must be at least ₹15,000", "salary")

        # Maximum reasonable salary (1 crore)
        if salary_decimal > Decimal("10000000"):
            result.add_error("Salary exceeds maximum allowed value", "salary")

        return result

    @staticmethod
    def work_hours(hours: Union[str, int, float]) -> ValidationResult:
        """Validate work hours per week"""
        result = ValidationResult()

        try:
            hours_float = float(hours)
        except (ValueError, TypeError):
            result.add_error("Work hours must be a valid number", "work_hours")
            return result

        if hours_float < 0:
            result.add_error("Work hours cannot be negative", "work_hours")
        elif hours_float > 48:  # Indian labor law limit
            result.add_error("Work hours cannot exceed 48 hours per week", "work_hours")

        return result


# ================== CUSTOMER VALIDATORS ==================


class CustomerValidators:
    """Validators for customer-related fields"""

    @staticmethod
    def loyalty_card(card_number: str) -> ValidationResult:
        """Validate loyalty card number"""
        result = ValidationResult()

        if not card_number:
            return result  # Loyalty card is optional

        card_number = card_number.strip()

        # Should be 10-16 digits
        if not re.match(r"^\d{10,16}$", card_number):
            result.add_error("Loyalty card must be 10-16 digits", "loyalty_card")

        return result

    @staticmethod
    def credit_limit(limit: Union[str, int, float, Decimal]) -> ValidationResult:
        """Validate customer credit limit"""
        result = ValidationResult()

        if not limit:
            return result  # Credit limit is optional

        try:
            limit_decimal = Decimal(str(limit))
        except (ValueError, InvalidOperation):
            result.add_error("Invalid credit limit format", "credit_limit")
            return result

        if limit_decimal < 0:
            result.add_error("Credit limit cannot be negative", "credit_limit")

        # Maximum credit limit (10 lakhs)
        if limit_decimal > Decimal("1000000"):
            result.add_error(
                "Credit limit exceeds maximum allowed value", "credit_limit"
            )

        return result


# ================== DATE/TIME VALIDATORS ==================


class DateTimeValidators:
    """Validators for date and time fields"""

    @staticmethod
    def date_range(
        start_date: Union[str, date], end_date: Union[str, date]
    ) -> ValidationResult:
        """Validate date range"""
        result = ValidationResult()

        try:
            if isinstance(start_date, str):
                start_dt = datetime.strptime(start_date, "%Y-%m-%d").date()
            else:
                start_dt = start_date

            if isinstance(end_date, str):
                end_dt = datetime.strptime(end_date, "%Y-%m-%d").date()
            else:
                end_dt = end_date

        except ValueError:
            result.add_error("Invalid date format (use YYYY-MM-DD)", "date")
            return result

        if start_dt > end_dt:
            result.add_error("Start date must be before end date", "date_range")

        return result

    @staticmethod
    def age_validation(
        birth_date: Union[str, date], min_age: int = 18, max_age: int = 100
    ) -> ValidationResult:
        """Validate age based on birth date"""
        result = ValidationResult()

        try:
            if isinstance(birth_date, str):
                birth_dt = datetime.strptime(birth_date, "%Y-%m-%d").date()
            else:
                birth_dt = birth_date
        except ValueError:
            result.add_error("Invalid birth date format (use YYYY-MM-DD)", "birth_date")
            return result

        today = date.today()
        age = (
            today.year
            - birth_dt.year
            - ((today.month, today.day) < (birth_dt.month, birth_dt.day))
        )

        if age < min_age:
            result.add_error(f"Age must be at least {min_age} years", "birth_date")
        elif age > max_age:
            result.add_error(f"Age cannot exceed {max_age} years", "birth_date")

        return result


# ================== COMPLEX OBJECT VALIDATORS ==================


class ComplexValidators:
    """Validators for complex objects and business logic"""

    @staticmethod
    def tenant_data(data: Dict[str, Any]) -> ValidationResult:
        """Validate tenant registration data"""
        result = ValidationResult()

        # Required fields
        required_fields = ["name", "subdomain", "admin_email", "plan"]
        for field in required_fields:
            field_result = BasicValidators.required(data.get(field), field)
            result.merge(field_result)

        if not result.is_valid:
            return result

        # Validate specific fields
        result.merge(BasicValidators.string_length(data["name"], 2, 100, "name"))
        result.merge(ContactValidators.email(data["admin_email"]))
        result.merge(
            BasicValidators.choice_validator(
                data["plan"],
                [
                    TenantConstants.PLAN_BASIC,
                    TenantConstants.PLAN_PROFESSIONAL,
                    TenantConstants.PLAN_ENTERPRISE,
                ],
                "plan",
            )
        )

        # Validate subdomain
        subdomain = data["subdomain"].lower().strip()
        if not re.match(TenantConstants.TENANT_SUBDOMAIN_PATTERN, subdomain):
            result.add_error("Invalid subdomain format", "subdomain")

        return result

    @staticmethod
    def store_data(data: Dict[str, Any]) -> ValidationResult:
        """Validate store registration data"""
        result = ValidationResult()

        # Required fields
        required_fields = ["name", "store_type", "address", "pincode", "manager_mobile"]
        for field in required_fields:
            field_result = BasicValidators.required(data.get(field), field)
            result.merge(field_result)

        if not result.is_valid:
            return result

        # Validate specific fields
        result.merge(BasicValidators.string_length(data["name"], 2, 200, "name"))
        result.merge(
            BasicValidators.choice_validator(
                data["store_type"],
                [
                    StoreConstants.STORE_TYPE_RETAIL,
                    StoreConstants.STORE_TYPE_OUTLET,
                    StoreConstants.STORE_TYPE_FLAGSHIP,
                    StoreConstants.STORE_TYPE_POP_UP,
                ],
                "store_type",
            )
        )
        result.merge(IndianDocumentValidators.indian_pincode(data["pincode"]))
        result.merge(ContactValidators.indian_mobile(data["manager_mobile"]))

        # Validate store hours if provided
        if data.get("open_time") and data.get("close_time"):
            result.merge(
                BusinessValidators.store_hours(data["open_time"], data["close_time"])
            )

        return result

    @staticmethod
    def employee_data(data: Dict[str, Any]) -> ValidationResult:
        """Validate employee registration data"""
        result = ValidationResult()

        # Required fields
        required_fields = [
            "first_name",
            "last_name",
            "email",
            "mobile",
            "role",
            "salary",
        ]
        for field in required_fields:
            field_result = BasicValidators.required(data.get(field), field)
            result.merge(field_result)

        if not result.is_valid:
            return result

        # Validate specific fields
        result.merge(
            BasicValidators.string_length(data["first_name"], 2, 50, "first_name")
        )
        result.merge(
            BasicValidators.string_length(data["last_name"], 2, 50, "last_name")
        )
        result.merge(ContactValidators.email(data["email"]))
        result.merge(ContactValidators.indian_mobile(data["mobile"]))
        result.merge(EmployeeValidators.salary(data["salary"]))

        # Validate optional fields
        if data.get("birth_date"):
            result.merge(DateTimeValidators.age_validation(data["birth_date"], 18, 70))

        if data.get("pan"):
            result.merge(IndianDocumentValidators.pan(data["pan"]))

        if data.get("aadhaar"):
            result.merge(IndianDocumentValidators.aadhaar(data["aadhaar"]))

        return result


# ================== PASSWORD VALIDATORS ==================


class PasswordValidators:
    """Validators for password strength"""

    @staticmethod
    def password_strength(password: str) -> ValidationResult:
        """Validate password strength for enterprise security"""
        result = ValidationResult()

        if not password:
            result.add_error("Password is required", "password")
            return result

        # Length check
        if len(password) < AuthConstants.MIN_PASSWORD_LENGTH:
            result.add_error(
                f"Password must be at least {AuthConstants.MIN_PASSWORD_LENGTH} characters long",
                "password",
            )

        if len(password) > AuthConstants.MAX_PASSWORD_LENGTH:
            result.add_error(
                f"Password must not exceed {AuthConstants.MAX_PASSWORD_LENGTH} characters",
                "password",
            )

        # Complexity checks
        if AuthConstants.REQUIRE_UPPERCASE and not re.search(r"[A-Z]", password):
            result.add_error(
                "Password must contain at least one uppercase letter", "password"
            )

        if AuthConstants.REQUIRE_LOWERCASE and not re.search(r"[a-z]", password):
            result.add_error(
                "Password must contain at least one lowercase letter", "password"
            )

        if AuthConstants.REQUIRE_NUMBERS and not re.search(r"\d", password):
            result.add_error("Password must contain at least one number", "password")

        if AuthConstants.REQUIRE_SPECIAL_CHARS and not re.search(
            r'[!@#$%^&*(),.?":{}|<>]', password
        ):
            result.add_error(
                "Password must contain at least one special character", "password"
            )

        # Common password check
        common_passwords = ["password", "123456", "admin", "password123", "admin123"]
        if password.lower() in common_passwords:
            result.add_error(
                "Password is too common, please choose a stronger password", "password"
            )

        return result


# Export all validator classes
__all__ = [
    "ValidationResult",
    "BasicValidators",
    "IndianDocumentValidators",
    "ContactValidators",
    "BusinessValidators",
    "EmployeeValidators",
    "CustomerValidators",
    "DateTimeValidators",
    "ComplexValidators",
    "PasswordValidators",
]
