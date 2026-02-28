"""
Enterprise Multi-Tenant Stores Management System Utilities
This module contains helper functions and utilities for the stores management platform.
"""

import re
import uuid
import hashlib
import secrets
import string
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Union, Tuple
from decimal import Decimal, ROUND_HALF_UP
import json

from app._core.utils.constants import (
    TenantConstants,
    StoreConstants,
    EmployeeConstants,
    ProductConstants,
    CustomerConstants,
    # RegexPatterns,
    BusinessConstants,
)


# ================== STRING UTILITIES ==================


def generate_id(prefix: str = "", length: int = 8) -> str:
    """Generate a unique ID with optional prefix"""
    random_part = "".join(
        secrets.choice(string.ascii_uppercase + string.digits) for _ in range(length)
    )
    return f"{prefix}{random_part}" if prefix else random_part


def generate_tenant_subdomain(tenant_name: str) -> str:
    """Generate a valid subdomain from tenant name"""
    # Remove special characters and convert to lowercase
    subdomain = re.sub(r"[^a-z0-9\-]", "", tenant_name.lower().replace(" ", "-"))

    # Ensure it starts and ends with alphanumeric
    subdomain = re.sub(r"^-+|-+$", "", subdomain)

    # Limit length
    subdomain = subdomain[:63]

    # Add random suffix if too short or already exists
    if len(subdomain) < 3:
        subdomain += generate_id(length=4).lower()

    # Validate against pattern
    if not re.match(TenantConstants.TENANT_SUBDOMAIN_PATTERN, subdomain):
        subdomain = f"tenant-{generate_id(length=6).lower()}"

    return subdomain


def generate_sku(category: str, subcategory: str = "", sequence: int = 1) -> str:
    """Generate a product SKU in format: CAT-SUB-001"""
    cat_code = category[:3].upper()
    sub_code = subcategory[:3].upper() if subcategory else "GEN"
    seq_code = f"{sequence:03d}"
    return f"{cat_code}-{sub_code}-{seq_code}"


def generate_employee_id(
    store_code: str, hire_date: datetime, sequence: int = 1
) -> str:
    """Generate employee ID: STORE-YYMM-001"""
    year_month = hire_date.strftime("%y%m")
    seq_code = f"{sequence:03d}"
    return f"{store_code.upper()}-{year_month}-{seq_code}"


def sanitize_string(text: str, max_length: int = None) -> str:
    """Sanitize string input for security and consistency"""
    if not text:
        return ""

    # Remove leading/trailing whitespace
    text = text.strip()

    # Remove control characters
    text = "".join(char for char in text if ord(char) >= 32)

    # Limit length if specified
    if max_length and len(text) > max_length:
        text = text[:max_length].strip()

    return text


def slugify(text: str) -> str:
    """Convert text to URL-friendly slug"""
    # Convert to lowercase and replace spaces with hyphens
    slug = re.sub(r"[^\w\s-]", "", text.lower())
    slug = re.sub(r"[\s_-]+", "-", slug)
    slug = slug.strip("-")
    return slug


# ================== VALIDATION UTILITIES ==================


def validate_email(email: str) -> bool:
    """Validate email format"""
    if not email or len(email) > 254:
        return False
    return re.match(RegexPatterns.EMAIL, email) is not None


def validate_phone(phone: str, country_code: str = "IN") -> bool:
    """Validate phone number format (default for India)"""
    if not phone:
        return False

    cleaned = re.sub(r"[^\d+]", "", phone)

    if country_code == "IN":
        indian_patterns = [r"^\+91[6-9]\d{9}$", r"^91[6-9]\d{9}$", r"^[6-9]\d{9}$"]
        return any(re.match(pattern, cleaned) for pattern in indian_patterns)

    return False


def validate_sku(sku: str) -> bool:
    """Validate SKU format"""
    if not sku:
        return False
    return (
        re.match(RegexPatterns.OBJECTID, sku) is not None
        or re.match(ProductConstants.SKU_PATTERN, sku) is not None
    )


def validate_barcode(barcode: str, barcode_type: str = "UPC") -> bool:
    """Validate barcode format based on type"""
    if not barcode:
        return False

    patterns = ProductConstants.BARCODE_PATTERNS
    if barcode_type not in patterns:
        return False

    return re.match(patterns[barcode_type], barcode) is not None


def validate_store_hours(open_time: str, close_time: str) -> bool:
    """Validate store operating hours"""
    try:
        open_dt = datetime.strptime(open_time, "%H:%M")
        close_dt = datetime.strptime(close_time, "%H:%M")

        # Handle overnight hours (e.g., 22:00 to 06:00)
        if close_dt < open_dt:
            close_dt += timedelta(days=1)

        # Store should be open for at least 1 hour and max 24 hours
        duration = close_dt - open_dt
        return timedelta(hours=1) <= duration <= timedelta(hours=24)
    except ValueError:
        return False


# ================== DATE & TIME UTILITIES ==================


def get_current_utc() -> datetime:
    """Get current UTC datetime"""
    return datetime.now(timezone.utc)


def format_datetime(dt: datetime, format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Format datetime to string"""
    return dt.strftime(format_str) if dt else ""


def parse_datetime(
    date_str: str, format_str: str = "%Y-%m-%d %H:%M:%S"
) -> Optional[datetime]:
    """Parse string to datetime"""
    try:
        return datetime.strptime(date_str, format_str)
    except (ValueError, TypeError):
        return None


def is_business_hours(current_time: datetime, open_time: str, close_time: str) -> bool:
    """Check if current time is within business hours"""
    try:
        current_time_only = current_time.time()
        open_dt = datetime.strptime(open_time, "%H:%M").time()
        close_dt = datetime.strptime(close_time, "%H:%M").time()

        # Handle overnight hours
        if close_dt < open_dt:
            return current_time_only >= open_dt or current_time_only <= close_dt
        else:
            return open_dt <= current_time_only <= close_dt
    except ValueError:
        return False


def get_indian_business_hours(business_type: str = "retail") -> Tuple[str, str]:
    """Get typical Indian business hours by business type"""
    business_hours = {
        "retail": ("10:00", "22:00"),
        "mall": ("10:00", "22:00"),
        "bank": ("10:00", "16:00"),
        "office": ("09:30", "18:30"),
        "restaurant": ("11:00", "23:00"),
        "medical": ("09:00", "21:00"),
        "grocery": ("08:00", "22:00"),
    }
    return business_hours.get(business_type, ("09:00", "18:00"))


def is_indian_holiday(date: datetime, state: str = "national") -> bool:
    """Check if date is an Indian holiday (basic implementation)"""
    # This is a basic implementation - in production, integrate with holiday API
    national_holidays = [
        (1, 26),  # Republic Day
        (8, 15),  # Independence Day
        (10, 2),  # Gandhi Jayanti
    ]

    month_day = (date.month, date.day)
    return month_day in national_holidays


def get_indian_timezone() -> str:
    """Get Indian Standard Time timezone"""
    return "Asia/Kolkata"


def convert_to_ist(utc_datetime: datetime) -> datetime:
    """Convert UTC datetime to Indian Standard Time"""
    import pytz

    utc_tz = pytz.UTC
    ist_tz = pytz.timezone("Asia/Kolkata")

    if utc_datetime.tzinfo is None:
        utc_datetime = utc_tz.localize(utc_datetime)

    return utc_datetime.astimezone(ist_tz)


def calculate_age(birth_date: datetime) -> int:
    """Calculate age from birth date"""
    today = datetime.now().date()
    birth = birth_date.date() if isinstance(birth_date, datetime) else birth_date
    return (
        today.year - birth.year - ((today.month, today.day) < (birth.month, birth.day))
    )


def get_week_boundaries(date: datetime = None) -> Tuple[datetime, datetime]:
    """Get start and end of week for given date"""
    if date is None:
        date = datetime.now()

    # Get Monday of the week
    start_of_week = date - timedelta(days=date.weekday())
    start_of_week = start_of_week.replace(hour=0, minute=0, second=0, microsecond=0)

    # Get Sunday of the week
    end_of_week = start_of_week + timedelta(days=6, hours=23, minutes=59, seconds=59)

    return start_of_week, end_of_week


# ================== FINANCIAL UTILITIES ==================


def format_currency(amount: Union[float, Decimal], currency: str = "INR") -> str:
    """Format amount as currency (default INR for India)"""
    if amount is None:
        return f"0.00 {currency}"

    # Convert to Decimal for precision
    decimal_amount = Decimal(str(amount)).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_UP
    )

    # Indian number formatting (lakhs, crores)
    if currency == "INR":
        return format_inr_currency(decimal_amount)
    else:
        return f"{decimal_amount:,.2f} {currency}"


def format_inr_currency(amount: Decimal) -> str:
    """Format amount in Indian Rupee format with lakhs/crores"""
    amount_str = f"{amount:,.2f}"

    # Convert to Indian numbering system
    if amount >= 10000000:  # 1 crore
        crores = amount / 10000000
        return f"₹{crores:.2f} Cr"
    elif amount >= 100000:  # 1 lakh
        lakhs = amount / 100000
        return f"₹{lakhs:.2f} L"
    else:
        return f"₹{amount_str}"


def calculate_gst(
    amount: Union[float, Decimal], gst_rate: Union[float, Decimal] = 18
) -> Dict[str, Decimal]:
    """Calculate GST components (CGST, SGST, IGST) for Indian businesses"""
    amount_decimal = Decimal(str(amount))
    gst_rate_decimal = Decimal(str(gst_rate)) / 100

    total_gst = amount_decimal * gst_rate_decimal

    # For intra-state: CGST + SGST (each half of total GST)
    # For inter-state: IGST (full GST)
    cgst_sgst = total_gst / 2

    return {
        "base_amount": amount_decimal.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP),
        "cgst": cgst_sgst.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP),
        "sgst": cgst_sgst.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP),
        "igst": total_gst.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP),
        "total_with_gst": (amount_decimal + total_gst).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        ),
    }


def calculate_discount(
    original_price: Union[float, Decimal], discount_percent: Union[float, Decimal]
) -> Decimal:
    """Calculate discount amount"""
    original_decimal = Decimal(str(original_price))
    discount_decimal = Decimal(str(discount_percent)) / 100

    discount_amount = original_decimal * discount_decimal
    return discount_amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def calculate_loyalty_points(amount: Union[float, Decimal], tier: str) -> int:
    """Calculate loyalty points earned"""
    earning_rates = CustomerConstants.LOYALTY_POINTS_EARNING_RATE
    rate = earning_rates.get(tier, 1)

    amount_decimal = Decimal(str(amount))
    points = amount_decimal * Decimal(str(rate))
    return int(points)


# ================== INVENTORY UTILITIES ==================


def calculate_reorder_point(
    daily_usage: int, lead_time_days: int, safety_stock: int = 0
) -> int:
    """Calculate inventory reorder point"""
    return (daily_usage * lead_time_days) + safety_stock


def categorize_stock_level(
    current_stock: int, low_threshold: int, critical_threshold: int
) -> str:
    """Categorize stock level status"""
    if current_stock <= critical_threshold:
        return "critical"
    elif current_stock <= low_threshold:
        return "low"
    elif current_stock >= BusinessConstants.OVERSTOCK_THRESHOLD:
        return "overstock"
    else:
        return "normal"


def calculate_inventory_turnover(
    cost_of_goods_sold: Decimal, average_inventory: Decimal
) -> Decimal:
    """Calculate inventory turnover ratio"""
    if average_inventory == 0:
        return Decimal("0")

    turnover = cost_of_goods_sold / average_inventory
    return turnover.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


# ================== PAGINATION UTILITIES ==================


def paginate_query(page: int, page_size: int, total_items: int) -> Dict[str, Any]:
    """Calculate pagination parameters"""
    # Validate inputs
    page = max(1, page)
    page_size = min(max(1, page_size), BusinessConstants.MAX_PAGE_SIZE)

    # Calculate pagination values
    total_pages = (total_items + page_size - 1) // page_size
    offset = (page - 1) * page_size

    # Determine if there are previous/next pages
    has_previous = page > 1
    has_next = page < total_pages

    return {
        "page": page,
        "page_size": page_size,
        "total_items": total_items,
        "total_pages": total_pages,
        "offset": offset,
        "has_previous": has_previous,
        "has_next": has_next,
        "previous_page": page - 1 if has_previous else None,
        "next_page": page + 1 if has_next else None,
    }


# ================== SECURITY UTILITIES ==================


def generate_secure_token(length: int = 32) -> str:
    """Generate cryptographically secure random token"""
    return secrets.token_urlsafe(length)


def hash_data(data: str, salt: str = None) -> str:
    """Hash data with optional salt"""
    if salt is None:
        salt = secrets.token_hex(16)

    hash_input = f"{data}{salt}".encode("utf-8")
    hash_object = hashlib.sha256(hash_input)
    return hash_object.hexdigest()


def mask_sensitive_data(data: str, mask_char: str = "*", visible_chars: int = 4) -> str:
    """Mask sensitive data (e.g., credit card numbers, SSN)"""
    if not data or len(data) <= visible_chars:
        return data

    visible_part = data[-visible_chars:]
    masked_part = mask_char * (len(data) - visible_chars)
    return f"{masked_part}{visible_part}"


def generate_correlation_id() -> str:
    """Generate correlation ID for request tracing"""
    return str(uuid.uuid4())


# ================== DATA TRANSFORMATION UTILITIES ==================


def flatten_dict(
    d: Dict[str, Any], parent_key: str = "", sep: str = "."
) -> Dict[str, Any]:
    """Flatten nested dictionary"""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def unflatten_dict(d: Dict[str, Any], sep: str = ".") -> Dict[str, Any]:
    """Unflatten dictionary with dot notation keys"""
    result = {}
    for key, value in d.items():
        keys = key.split(sep)
        current = result
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        current[keys[-1]] = value
    return result


def deep_merge_dicts(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """Deep merge two dictionaries"""
    result = dict1.copy()
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge_dicts(result[key], value)
        else:
            result[key] = value
    return result


def safe_json_loads(json_str: str, default: Any = None) -> Any:
    """Safely parse JSON string"""
    try:
        return json.loads(json_str)
    except (json.JSONDecodeError, TypeError):
        return default


def safe_json_dumps(obj: Any, default: str = "{}") -> str:
    """Safely serialize object to JSON"""
    try:
        return json.dumps(obj, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        return default


# ================== FILE UTILITIES ==================


def get_file_extension(filename: str) -> str:
    """Get file extension from filename"""
    return filename.split(".")[-1].lower() if "." in filename else ""


def is_allowed_file_type(filename: str, allowed_extensions: List[str]) -> bool:
    """Check if file type is allowed"""
    extension = f".{get_file_extension(filename)}"
    return extension in allowed_extensions


def format_file_size(size_bytes: int) -> str:
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0 B"

    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    size = float(size_bytes)

    while size >= 1024.0 and i < len(size_names) - 1:
        size /= 1024.0
        i += 1

    return f"{size:.1f} {size_names[i]}"


# ================== SEARCH & FILTER UTILITIES ==================


def build_search_query(search_term: str, fields: List[str]) -> Dict[str, Any]:
    """Build MongoDB search query for multiple fields"""
    if not search_term:
        return {}

    # Escape special regex characters
    escaped_term = re.escape(search_term)

    # Create case-insensitive regex pattern
    regex_pattern = {"$regex": escaped_term, "$options": "i"}

    # Build OR query for all specified fields
    or_conditions = [{field: regex_pattern} for field in fields]

    return {"$or": or_conditions}


def apply_filters(
    base_query: Dict[str, Any], filters: Dict[str, Any]
) -> Dict[str, Any]:
    """Apply filters to MongoDB query"""
    query = base_query.copy()

    for field, value in filters.items():
        if value is not None and value != "":
            # Handle range filters (e.g., price_min, price_max)
            if field.endswith("_min"):
                base_field = field[:-4]
                query[base_field] = query.get(base_field, {})
                query[base_field]["$gte"] = value
            elif field.endswith("_max"):
                base_field = field[:-4]
                query[base_field] = query.get(base_field, {})
                query[base_field]["$lte"] = value
            # Handle array filters (e.g., categories)
            elif isinstance(value, list):
                query[field] = {"$in": value}
            # Handle exact matches
            else:
                query[field] = value

    return query


# ================== BUSINESS LOGIC HELPERS ==================


def calculate_shift_duration(start_time: str, end_time: str) -> float:
    """Calculate shift duration in hours"""
    try:
        start = datetime.strptime(start_time, "%H:%M")
        end = datetime.strptime(end_time, "%H:%M")

        # Handle overnight shifts
        if end < start:
            end += timedelta(days=1)

        duration = end - start
        return duration.total_seconds() / 3600  # Convert to hours
    except ValueError:
        return 0.0


def is_peak_hours(
    current_time: datetime, peak_start: str = "11:00", peak_end: str = "14:00"
) -> bool:
    """Check if current time is during peak business hours"""
    return is_business_hours(current_time, peak_start, peak_end)


def calculate_commission(
    sales_amount: Decimal, commission_rate: Decimal, tier: str = "basic"
) -> Decimal:
    """Calculate sales commission based on amount and tier"""
    base_commission = sales_amount * commission_rate

    # Tier-based multipliers
    tier_multipliers = {
        "basic": Decimal("1.0"),
        "silver": Decimal("1.1"),
        "gold": Decimal("1.2"),
        "platinum": Decimal("1.3"),
    }

    multiplier = tier_multipliers.get(tier, Decimal("1.0"))
    final_commission = base_commission * multiplier

    return final_commission.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


# Export all helper functions
__all__ = [
    # String utilities
    "generate_id",
    "generate_tenant_subdomain",
    "generate_sku",
    "generate_employee_id",
    "sanitize_string",
    "slugify",
    # Validation utilities
    "validate_email",
    "validate_phone",
    "validate_sku",
    "validate_barcode",
    "validate_store_hours",
    # Date & time utilities
    "get_current_utc",
    "format_datetime",
    "parse_datetime",
    "is_business_hours",
    "get_shift_hours",
    "calculate_age",
    "get_week_boundaries",
    # Financial utilities
    "format_currency",
    "calculate_tax",
    "calculate_discount",
    "calculate_loyalty_points",
    # Inventory utilities
    "calculate_reorder_point",
    "categorize_stock_level",
    "calculate_inventory_turnover",
    # Pagination utilities
    "paginate_query",
    # Security utilities
    "generate_secure_token",
    "hash_data",
    "mask_sensitive_data",
    "generate_correlation_id",
    # Data transformation utilities
    "flatten_dict",
    "unflatten_dict",
    "deep_merge_dicts",
    "safe_json_loads",
    "safe_json_dumps",
    # File utilities
    "get_file_extension",
    "is_allowed_file_type",
    "format_file_size",
    # Search & filter utilities
    "build_search_query",
    "apply_filters",
    # Business logic helpers
    "calculate_shift_duration",
    "is_peak_hours",
    "calculate_commission",
]


def validate_sku(sku: str) -> bool:
    """Validate SKU format"""
    if not sku:
        return False
    return (
        re.match(RegexPatterns.OBJECTID, sku) is not None
        or re.match(ProductConstants.SKU_PATTERN, sku) is not None
    )


def validate_barcode(barcode: str, barcode_type: str = "UPC") -> bool:
    """Validate barcode format based on type"""
    if not barcode:
        return False

    patterns = ProductConstants.BARCODE_PATTERNS
    if barcode_type not in patterns:
        return False

    return re.match(patterns[barcode_type], barcode) is not None


def validate_store_hours(open_time: str, close_time: str) -> bool:
    """Validate store operating hours"""
    try:
        open_dt = datetime.strptime(open_time, "%H:%M")
        close_dt = datetime.strptime(close_time, "%H:%M")

        # Handle overnight hours (e.g., 22:00 to 06:00)
        if close_dt < open_dt:
            close_dt += timedelta(days=1)

        # Store should be open for at least 1 hour and max 24 hours
        duration = close_dt - open_dt
        return timedelta(hours=1) <= duration <= timedelta(hours=24)
    except ValueError:
        return False


# ================== DATE & TIME UTILITIES ==================


def get_current_utc() -> datetime:
    """Get current UTC datetime"""
    return datetime.now(timezone.utc)


def format_datetime(dt: datetime, format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Format datetime to string"""
    return dt.strftime(format_str) if dt else ""


def parse_datetime(
    date_str: str, format_str: str = "%Y-%m-%d %H:%M:%S"
) -> Optional[datetime]:
    """Parse string to datetime"""
    try:
        return datetime.strptime(date_str, format_str)
    except (ValueError, TypeError):
        return None


def is_business_hours(current_time: datetime, open_time: str, close_time: str) -> bool:
    """Check if current time is within business hours"""
    try:
        current_time_only = current_time.time()
        open_dt = datetime.strptime(open_time, "%H:%M").time()
        close_dt = datetime.strptime(close_time, "%H:%M").time()

        # Handle overnight hours
        if close_dt < open_dt:
            return current_time_only >= open_dt or current_time_only <= close_dt
        else:
            return open_dt <= current_time_only <= close_dt
    except ValueError:
        return False


def get_shift_hours(shift_type: str) -> Tuple[str, str]:
    """Get start and end times for shift types"""
    shift_hours = {
        EmployeeConstants.SHIFT_TYPE_MORNING: ("06:00", "14:00"),
        EmployeeConstants.SHIFT_TYPE_AFTERNOON: ("14:00", "22:00"),
        EmployeeConstants.SHIFT_TYPE_EVENING: ("22:00", "06:00"),
    }
    return shift_hours.get(shift_type, ("09:00", "17:00"))


def calculate_age(birth_date: datetime) -> int:
    """Calculate age from birth date"""
    today = datetime.now().date()
    birth = birth_date.date() if isinstance(birth_date, datetime) else birth_date
    return (
        today.year - birth.year - ((today.month, today.day) < (birth.month, birth.day))
    )


def get_week_boundaries(date: datetime = None) -> Tuple[datetime, datetime]:
    """Get start and end of week for given date"""
    if date is None:
        date = datetime.now()

    # Get Monday of the week
    start_of_week = date - timedelta(days=date.weekday())
    start_of_week = start_of_week.replace(hour=0, minute=0, second=0, microsecond=0)

    # Get Sunday of the week
    end_of_week = start_of_week + timedelta(days=6, hours=23, minutes=59, seconds=59)

    return start_of_week, end_of_week


# ================== FINANCIAL UTILITIES ==================


def format_currency(amount: Union[float, Decimal], currency: str = "INR") -> str:
    """Format amount as currency (default INR for India)"""
    if amount is None:
        return f"0.00 {currency}"

    # Convert to Decimal for precision
    decimal_amount = Decimal(str(amount)).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_UP
    )

    # Indian number formatting (lakhs, crores)
    if currency == "INR":
        return format_inr_currency(decimal_amount)
    else:
        return f"{decimal_amount:,.2f} {currency}"


def format_inr_currency(amount: Decimal) -> str:
    """Format amount in Indian Rupee format with lakhs/crores"""
    amount_str = f"{amount:,.2f}"

    # Convert to Indian numbering system
    if amount >= 10000000:  # 1 crore
        crores = amount / 10000000
        return f"₹{crores:.2f} Cr"
    elif amount >= 100000:  # 1 lakh
        lakhs = amount / 100000
        return f"₹{lakhs:.2f} L"
    else:
        return f"₹{amount_str}"


def calculate_tax(
    subtotal: Union[float, Decimal], tax_rate: Union[float, Decimal]
) -> Decimal:
    """Calculate tax amount"""
    subtotal_decimal = Decimal(str(subtotal))
    tax_rate_decimal = Decimal(str(tax_rate))

    tax_amount = subtotal_decimal * tax_rate_decimal
    return tax_amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def calculate_discount(
    original_price: Union[float, Decimal], discount_percent: Union[float, Decimal]
) -> Decimal:
    """Calculate discount amount"""
    original_decimal = Decimal(str(original_price))
    discount_decimal = Decimal(str(discount_percent)) / 100

    discount_amount = original_decimal * discount_decimal
    return discount_amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def calculate_loyalty_points(amount: Union[float, Decimal], tier: str) -> int:
    """Calculate loyalty points earned"""
    earning_rates = CustomerConstants.LOYALTY_POINTS_EARNING_RATE
    rate = earning_rates.get(tier, 1)

    amount_decimal = Decimal(str(amount))
    points = amount_decimal * Decimal(str(rate))
    return int(points)


# ================== INVENTORY UTILITIES ==================


def calculate_reorder_point(
    daily_usage: int, lead_time_days: int, safety_stock: int = 0
) -> int:
    """Calculate inventory reorder point"""
    return (daily_usage * lead_time_days) + safety_stock


def categorize_stock_level(
    current_stock: int, low_threshold: int, critical_threshold: int
) -> str:
    """Categorize stock level status"""
    if current_stock <= critical_threshold:
        return "critical"
    elif current_stock <= low_threshold:
        return "low"
    elif current_stock >= BusinessConstants.OVERSTOCK_THRESHOLD:
        return "overstock"
    else:
        return "normal"


def calculate_inventory_turnover(
    cost_of_goods_sold: Decimal, average_inventory: Decimal
) -> Decimal:
    """Calculate inventory turnover ratio"""
    if average_inventory == 0:
        return Decimal("0")

    turnover = cost_of_goods_sold / average_inventory
    return turnover.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


# ================== PAGINATION UTILITIES ==================


def paginate_query(page: int, page_size: int, total_items: int) -> Dict[str, Any]:
    """Calculate pagination parameters"""
    # Validate inputs
    page = max(1, page)
    page_size = min(max(1, page_size), BusinessConstants.MAX_PAGE_SIZE)

    # Calculate pagination values
    total_pages = (total_items + page_size - 1) // page_size
    offset = (page - 1) * page_size

    # Determine if there are previous/next pages
    has_previous = page > 1
    has_next = page < total_pages

    return {
        "page": page,
        "page_size": page_size,
        "total_items": total_items,
        "total_pages": total_pages,
        "offset": offset,
        "has_previous": has_previous,
        "has_next": has_next,
        "previous_page": page - 1 if has_previous else None,
        "next_page": page + 1 if has_next else None,
    }


# ================== SECURITY UTILITIES ==================


def generate_secure_token(length: int = 32) -> str:
    """Generate cryptographically secure random token"""
    return secrets.token_urlsafe(length)


def hash_data(data: str, salt: str = None) -> str:
    """Hash data with optional salt"""
    if salt is None:
        salt = secrets.token_hex(16)

    hash_input = f"{data}{salt}".encode("utf-8")
    hash_object = hashlib.sha256(hash_input)
    return hash_object.hexdigest()


def mask_sensitive_data(data: str, mask_char: str = "*", visible_chars: int = 4) -> str:
    """Mask sensitive data (e.g., credit card numbers, SSN)"""
    if not data or len(data) <= visible_chars:
        return data

    visible_part = data[-visible_chars:]
    masked_part = mask_char * (len(data) - visible_chars)
    return f"{masked_part}{visible_part}"


def generate_correlation_id() -> str:
    """Generate correlation ID for request tracing"""
    return str(uuid.uuid4())


# ================== DATA TRANSFORMATION UTILITIES ==================


def flatten_dict(
    d: Dict[str, Any], parent_key: str = "", sep: str = "."
) -> Dict[str, Any]:
    """Flatten nested dictionary"""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def unflatten_dict(d: Dict[str, Any], sep: str = ".") -> Dict[str, Any]:
    """Unflatten dictionary with dot notation keys"""
    result = {}
    for key, value in d.items():
        keys = key.split(sep)
        current = result
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        current[keys[-1]] = value
    return result


def deep_merge_dicts(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """Deep merge two dictionaries"""
    result = dict1.copy()
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge_dicts(result[key], value)
        else:
            result[key] = value
    return result


def safe_json_loads(json_str: str, default: Any = None) -> Any:
    """Safely parse JSON string"""
    try:
        return json.loads(json_str)
    except (json.JSONDecodeError, TypeError):
        return default


def safe_json_dumps(obj: Any, default: str = "{}") -> str:
    """Safely serialize object to JSON"""
    try:
        return json.dumps(obj, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        return default


# ================== FILE UTILITIES ==================


def get_file_extension(filename: str) -> str:
    """Get file extension from filename"""
    return filename.split(".")[-1].lower() if "." in filename else ""


def is_allowed_file_type(filename: str, allowed_extensions: List[str]) -> bool:
    """Check if file type is allowed"""
    extension = f".{get_file_extension(filename)}"
    return extension in allowed_extensions


def format_file_size(size_bytes: int) -> str:
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0 B"

    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    size = float(size_bytes)

    while size >= 1024.0 and i < len(size_names) - 1:
        size /= 1024.0
        i += 1

    return f"{size:.1f} {size_names[i]}"


# ================== SEARCH & FILTER UTILITIES ==================


def build_search_query(search_term: str, fields: List[str]) -> Dict[str, Any]:
    """Build MongoDB search query for multiple fields"""
    if not search_term:
        return {}

    # Escape special regex characters
    escaped_term = re.escape(search_term)

    # Create case-insensitive regex pattern
    regex_pattern = {"$regex": escaped_term, "$options": "i"}

    # Build OR query for all specified fields
    or_conditions = [{field: regex_pattern} for field in fields]

    return {"$or": or_conditions}


def apply_filters(
    base_query: Dict[str, Any], filters: Dict[str, Any]
) -> Dict[str, Any]:
    """Apply filters to MongoDB query"""
    query = base_query.copy()

    for field, value in filters.items():
        if value is not None and value != "":
            # Handle range filters (e.g., price_min, price_max)
            if field.endswith("_min"):
                base_field = field[:-4]
                query[base_field] = query.get(base_field, {})
                query[base_field]["$gte"] = value
            elif field.endswith("_max"):
                base_field = field[:-4]
                query[base_field] = query.get(base_field, {})
                query[base_field]["$lte"] = value
            # Handle array filters (e.g., categories)
            elif isinstance(value, list):
                query[field] = {"$in": value}
            # Handle exact matches
            else:
                query[field] = value

    return query


# ================== BUSINESS LOGIC HELPERS ==================


def calculate_shift_duration(start_time: str, end_time: str) -> float:
    """Calculate shift duration in hours"""
    try:
        start = datetime.strptime(start_time, "%H:%M")
        end = datetime.strptime(end_time, "%H:%M")

        # Handle overnight shifts
        if end < start:
            end += timedelta(days=1)

        duration = end - start
        return duration.total_seconds() / 3600  # Convert to hours
    except ValueError:
        return 0.0


def is_peak_hours(
    current_time: datetime, peak_start: str = "11:00", peak_end: str = "14:00"
) -> bool:
    """Check if current time is during peak business hours"""
    return is_business_hours(current_time, peak_start, peak_end)


def calculate_commission(
    sales_amount: Decimal, commission_rate: Decimal, tier: str = "basic"
) -> Decimal:
    """Calculate sales commission based on amount and tier"""
    base_commission = sales_amount * commission_rate

    # Tier-based multipliers
    tier_multipliers = {
        "basic": Decimal("1.0"),
        "silver": Decimal("1.1"),
        "gold": Decimal("1.2"),
        "platinum": Decimal("1.3"),
    }

    multiplier = tier_multipliers.get(tier, Decimal("1.0"))
    final_commission = base_commission * multiplier

    return final_commission.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


# Export all helper functions
__all__ = [
    # String utilities
    "generate_id",
    "generate_tenant_subdomain",
    "generate_sku",
    "generate_employee_id",
    "sanitize_string",
    "slugify",
    # Validation utilities
    "validate_email",
    "validate_phone",
    "validate_sku",
    "validate_barcode",
    "validate_store_hours",
    # Date & time utilities
    "get_current_utc",
    "format_datetime",
    "parse_datetime",
    "is_business_hours",
    "get_shift_hours",
    "calculate_age",
    "get_week_boundaries",
    # Financial utilities
    "format_currency",
    "calculate_tax",
    "calculate_discount",
    "calculate_loyalty_points",
    # Inventory utilities
    "calculate_reorder_point",
    "categorize_stock_level",
    "calculate_inventory_turnover",
    # Pagination utilities
    "paginate_query",
    # Security utilities
    "generate_secure_token",
    "hash_data",
    "mask_sensitive_data",
    "generate_correlation_id",
    # Data transformation utilities
    "flatten_dict",
    "unflatten_dict",
    "deep_merge_dicts",
    "safe_json_loads",
    "safe_json_dumps",
    # File utilities
    "get_file_extension",
    "is_allowed_file_type",
    "format_file_size",
    # Search & filter utilities
    "build_search_query",
    "apply_filters",
    # Business logic helpers
    "calculate_shift_duration",
    "is_peak_hours",
    "calculate_commission",
]


def validate_sku(sku: str) -> bool:
    """Validate SKU format"""
    if not sku:
        return False
    return (
        re.match(RegexPatterns.OBJECTID, sku) is not None
        or re.match(ProductConstants.SKU_PATTERN, sku) is not None
    )


def validate_barcode(barcode: str, barcode_type: str = "UPC") -> bool:
    """Validate barcode format based on type"""
    if not barcode:
        return False

    patterns = ProductConstants.BARCODE_PATTERNS
    if barcode_type not in patterns:
        return False

    return re.match(patterns[barcode_type], barcode) is not None


def validate_store_hours(open_time: str, close_time: str) -> bool:
    """Validate store operating hours"""
    try:
        open_dt = datetime.strptime(open_time, "%H:%M")
        close_dt = datetime.strptime(close_time, "%H:%M")

        # Handle overnight hours (e.g., 22:00 to 06:00)
        if close_dt < open_dt:
            close_dt += timedelta(days=1)

        # Store should be open for at least 1 hour and max 24 hours
        duration = close_dt - open_dt
        return timedelta(hours=1) <= duration <= timedelta(hours=24)
    except ValueError:
        return False


# ================== DATE & TIME UTILITIES ==================


def get_current_utc() -> datetime:
    """Get current UTC datetime"""
    return datetime.now(timezone.utc)


def format_datetime(dt: datetime, format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Format datetime to string"""
    return dt.strftime(format_str) if dt else ""


def parse_datetime(
    date_str: str, format_str: str = "%Y-%m-%d %H:%M:%S"
) -> Optional[datetime]:
    """Parse string to datetime"""
    try:
        return datetime.strptime(date_str, format_str)
    except (ValueError, TypeError):
        return None


def is_business_hours(current_time: datetime, open_time: str, close_time: str) -> bool:
    """Check if current time is within business hours"""
    try:
        current_time_only = current_time.time()
        open_dt = datetime.strptime(open_time, "%H:%M").time()
        close_dt = datetime.strptime(close_time, "%H:%M").time()

        # Handle overnight hours
        if close_dt < open_dt:
            return current_time_only >= open_dt or current_time_only <= close_dt
        else:
            return open_dt <= current_time_only <= close_dt
    except ValueError:
        return False


def get_shift_hours(shift_type: str) -> Tuple[str, str]:
    """Get start and end times for shift types"""
    shift_hours = {
        EmployeeConstants.SHIFT_TYPE_MORNING: ("06:00", "14:00"),
        EmployeeConstants.SHIFT_TYPE_AFTERNOON: ("14:00", "22:00"),
        EmployeeConstants.SHIFT_TYPE_EVENING: ("22:00", "06:00"),
    }
    return shift_hours.get(shift_type, ("09:00", "17:00"))


def calculate_age(birth_date: datetime) -> int:
    """Calculate age from birth date"""
    today = datetime.now().date()
    birth = birth_date.date() if isinstance(birth_date, datetime) else birth_date
    return (
        today.year - birth.year - ((today.month, today.day) < (birth.month, birth.day))
    )


def get_week_boundaries(date: datetime = None) -> Tuple[datetime, datetime]:
    """Get start and end of week for given date"""
    if date is None:
        date = datetime.now()

    # Get Monday of the week
    start_of_week = date - timedelta(days=date.weekday())
    start_of_week = start_of_week.replace(hour=0, minute=0, second=0, microsecond=0)

    # Get Sunday of the week
    end_of_week = start_of_week + timedelta(days=6, hours=23, minutes=59, seconds=59)

    return start_of_week, end_of_week


# ================== FINANCIAL UTILITIES ==================


def format_currency(amount: Union[float, Decimal], currency: str = "INR") -> str:
    """Format amount as currency (default INR for India)"""
    if amount is None:
        return f"0.00 {currency}"

    # Convert to Decimal for precision
    decimal_amount = Decimal(str(amount)).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_UP
    )

    # Indian number formatting (lakhs, crores)
    if currency == "INR":
        return format_inr_currency(decimal_amount)
    else:
        return f"{decimal_amount:,.2f} {currency}"


def format_inr_currency(amount: Decimal) -> str:
    """Format amount in Indian Rupee format with lakhs/crores"""
    amount_str = f"{amount:,.2f}"

    # Convert to Indian numbering system
    if amount >= 10000000:  # 1 crore
        crores = amount / 10000000
        return f"₹{crores:.2f} Cr"
    elif amount >= 100000:  # 1 lakh
        lakhs = amount / 100000
        return f"₹{lakhs:.2f} L"
    else:
        return f"₹{amount_str}"


def calculate_tax(
    subtotal: Union[float, Decimal], tax_rate: Union[float, Decimal]
) -> Decimal:
    """Calculate tax amount"""
    subtotal_decimal = Decimal(str(subtotal))
    tax_rate_decimal = Decimal(str(tax_rate))

    tax_amount = subtotal_decimal * tax_rate_decimal
    return tax_amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def calculate_discount(
    original_price: Union[float, Decimal], discount_percent: Union[float, Decimal]
) -> Decimal:
    """Calculate discount amount"""
    original_decimal = Decimal(str(original_price))
    discount_decimal = Decimal(str(discount_percent)) / 100

    discount_amount = original_decimal * discount_decimal
    return discount_amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def calculate_loyalty_points(amount: Union[float, Decimal], tier: str) -> int:
    """Calculate loyalty points earned"""
    earning_rates = CustomerConstants.LOYALTY_POINTS_EARNING_RATE
    rate = earning_rates.get(tier, 1)

    amount_decimal = Decimal(str(amount))
    points = amount_decimal * Decimal(str(rate))
    return int(points)


# ================== INVENTORY UTILITIES ==================


def calculate_reorder_point(
    daily_usage: int, lead_time_days: int, safety_stock: int = 0
) -> int:
    """Calculate inventory reorder point"""
    return (daily_usage * lead_time_days) + safety_stock


def categorize_stock_level(
    current_stock: int, low_threshold: int, critical_threshold: int
) -> str:
    """Categorize stock level status"""
    if current_stock <= critical_threshold:
        return "critical"
    elif current_stock <= low_threshold:
        return "low"
    elif current_stock >= BusinessConstants.OVERSTOCK_THRESHOLD:
        return "overstock"
    else:
        return "normal"


def calculate_inventory_turnover(
    cost_of_goods_sold: Decimal, average_inventory: Decimal
) -> Decimal:
    """Calculate inventory turnover ratio"""
    if average_inventory == 0:
        return Decimal("0")

    turnover = cost_of_goods_sold / average_inventory
    return turnover.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


# ================== PAGINATION UTILITIES ==================


def paginate_query(page: int, page_size: int, total_items: int) -> Dict[str, Any]:
    """Calculate pagination parameters"""
    # Validate inputs
    page = max(1, page)
    page_size = min(max(1, page_size), BusinessConstants.MAX_PAGE_SIZE)

    # Calculate pagination values
    total_pages = (total_items + page_size - 1) // page_size
    offset = (page - 1) * page_size

    # Determine if there are previous/next pages
    has_previous = page > 1
    has_next = page < total_pages

    return {
        "page": page,
        "page_size": page_size,
        "total_items": total_items,
        "total_pages": total_pages,
        "offset": offset,
        "has_previous": has_previous,
        "has_next": has_next,
        "previous_page": page - 1 if has_previous else None,
        "next_page": page + 1 if has_next else None,
    }


# ================== SECURITY UTILITIES ==================


def generate_secure_token(length: int = 32) -> str:
    """Generate cryptographically secure random token"""
    return secrets.token_urlsafe(length)


def hash_data(data: str, salt: str = None) -> str:
    """Hash data with optional salt"""
    if salt is None:
        salt = secrets.token_hex(16)

    hash_input = f"{data}{salt}".encode("utf-8")
    hash_object = hashlib.sha256(hash_input)
    return hash_object.hexdigest()


def mask_sensitive_data(data: str, mask_char: str = "*", visible_chars: int = 4) -> str:
    """Mask sensitive data (e.g., credit card numbers, SSN)"""
    if not data or len(data) <= visible_chars:
        return data

    visible_part = data[-visible_chars:]
    masked_part = mask_char * (len(data) - visible_chars)
    return f"{masked_part}{visible_part}"


def generate_correlation_id() -> str:
    """Generate correlation ID for request tracing"""
    return str(uuid.uuid4())


# ================== DATA TRANSFORMATION UTILITIES ==================


def flatten_dict(
    d: Dict[str, Any], parent_key: str = "", sep: str = "."
) -> Dict[str, Any]:
    """Flatten nested dictionary"""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def unflatten_dict(d: Dict[str, Any], sep: str = ".") -> Dict[str, Any]:
    """Unflatten dictionary with dot notation keys"""
    result = {}
    for key, value in d.items():
        keys = key.split(sep)
        current = result
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        current[keys[-1]] = value
    return result


def deep_merge_dicts(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """Deep merge two dictionaries"""
    result = dict1.copy()
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge_dicts(result[key], value)
        else:
            result[key] = value
    return result


def safe_json_loads(json_str: str, default: Any = None) -> Any:
    """Safely parse JSON string"""
    try:
        return json.loads(json_str)
    except (json.JSONDecodeError, TypeError):
        return default


def safe_json_dumps(obj: Any, default: str = "{}") -> str:
    """Safely serialize object to JSON"""
    try:
        return json.dumps(obj, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        return default


# ================== FILE UTILITIES ==================


def get_file_extension(filename: str) -> str:
    """Get file extension from filename"""
    return filename.split(".")[-1].lower() if "." in filename else ""


def is_allowed_file_type(filename: str, allowed_extensions: List[str]) -> bool:
    """Check if file type is allowed"""
    extension = f".{get_file_extension(filename)}"
    return extension in allowed_extensions


def format_file_size(size_bytes: int) -> str:
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0 B"

    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    size = float(size_bytes)

    while size >= 1024.0 and i < len(size_names) - 1:
        size /= 1024.0
        i += 1

    return f"{size:.1f} {size_names[i]}"


# ================== SEARCH & FILTER UTILITIES ==================


def build_search_query(search_term: str, fields: List[str]) -> Dict[str, Any]:
    """Build MongoDB search query for multiple fields"""
    if not search_term:
        return {}

    # Escape special regex characters
    escaped_term = re.escape(search_term)

    # Create case-insensitive regex pattern
    regex_pattern = {"$regex": escaped_term, "$options": "i"}

    # Build OR query for all specified fields
    or_conditions = [{field: regex_pattern} for field in fields]

    return {"$or": or_conditions}


def apply_filters(
    base_query: Dict[str, Any], filters: Dict[str, Any]
) -> Dict[str, Any]:
    """Apply filters to MongoDB query"""
    query = base_query.copy()

    for field, value in filters.items():
        if value is not None and value != "":
            # Handle range filters (e.g., price_min, price_max)
            if field.endswith("_min"):
                base_field = field[:-4]
                query[base_field] = query.get(base_field, {})
                query[base_field]["$gte"] = value
            elif field.endswith("_max"):
                base_field = field[:-4]
                query[base_field] = query.get(base_field, {})
                query[base_field]["$lte"] = value
            # Handle array filters (e.g., categories)
            elif isinstance(value, list):
                query[field] = {"$in": value}
            # Handle exact matches
            else:
                query[field] = value

    return query


# ================== BUSINESS LOGIC HELPERS ==================


def calculate_shift_duration(start_time: str, end_time: str) -> float:
    """Calculate shift duration in hours"""
    try:
        start = datetime.strptime(start_time, "%H:%M")
        end = datetime.strptime(end_time, "%H:%M")

        # Handle overnight shifts
        if end < start:
            end += timedelta(days=1)

        duration = end - start
        return duration.total_seconds() / 3600  # Convert to hours
    except ValueError:
        return 0.0


def is_peak_hours(
    current_time: datetime, peak_start: str = "11:00", peak_end: str = "14:00"
) -> bool:
    """Check if current time is during peak business hours"""
    return is_business_hours(current_time, peak_start, peak_end)


def calculate_commission(
    sales_amount: Decimal, commission_rate: Decimal, tier: str = "basic"
) -> Decimal:
    """Calculate sales commission based on amount and tier"""
    base_commission = sales_amount * commission_rate

    # Tier-based multipliers
    tier_multipliers = {
        "basic": Decimal("1.0"),
        "silver": Decimal("1.1"),
        "gold": Decimal("1.2"),
        "platinum": Decimal("1.3"),
    }

    multiplier = tier_multipliers.get(tier, Decimal("1.0"))
    final_commission = base_commission * multiplier

    return final_commission.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


# Export all helper functions
__all__ = [
    # String utilities
    "generate_id",
    "generate_tenant_subdomain",
    "generate_sku",
    "generate_employee_id",
    "sanitize_string",
    "slugify",
    # Validation utilities
    "validate_email",
    "validate_phone",
    "validate_sku",
    "validate_barcode",
    "validate_store_hours",
    # Date & time utilities
    "get_current_utc",
    "format_datetime",
    "parse_datetime",
    "is_business_hours",
    "get_shift_hours",
    "calculate_age",
    "get_week_boundaries",
    # Financial utilities
    "format_currency",
    "calculate_tax",
    "calculate_discount",
    "calculate_loyalty_points",
    # Inventory utilities
    "calculate_reorder_point",
    "categorize_stock_level",
    "calculate_inventory_turnover",
    # Pagination utilities
    "paginate_query",
    # Security utilities
    "generate_secure_token",
    "hash_data",
    "mask_sensitive_data",
    "generate_correlation_id",
    # Data transformation utilities
    "flatten_dict",
    "unflatten_dict",
    "deep_merge_dicts",
    "safe_json_loads",
    "safe_json_dumps",
    # File utilities
    "get_file_extension",
    "is_allowed_file_type",
    "format_file_size",
    # Search & filter utilities
    "build_search_query",
    "apply_filters",
    # Business logic helpers
    "calculate_shift_duration",
    "is_peak_hours",
    "calculate_commission",
]


def validate_gstin(gstin: str) -> bool:
    """Validate Indian GST Identification Number"""
    if not gstin or len(gstin) != 15:
        return False

    # GSTIN format: 2 digits state code + 10 digits PAN + 1 digit entity + 1 digit Z + 1 check digit
    gstin_pattern = r"^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}[Z]{1}[0-9A-Z]{1}$"
    return re.match(gstin_pattern, gstin) is not None


def validate_sku(sku: str) -> bool:
    """Validate SKU format"""
    if not sku:
        return False
    return (
        re.match(RegexPatterns.OBJECTID, sku) is not None
        or re.match(ProductConstants.SKU_PATTERN, sku) is not None
    )


def validate_barcode(barcode: str, barcode_type: str = "UPC") -> bool:
    """Validate barcode format based on type"""
    if not barcode:
        return False

    patterns = ProductConstants.BARCODE_PATTERNS
    if barcode_type not in patterns:
        return False

    return re.match(patterns[barcode_type], barcode) is not None


def validate_store_hours(open_time: str, close_time: str) -> bool:
    """Validate store operating hours"""
    try:
        open_dt = datetime.strptime(open_time, "%H:%M")
        close_dt = datetime.strptime(close_time, "%H:%M")

        # Handle overnight hours (e.g., 22:00 to 06:00)
        if close_dt < open_dt:
            close_dt += timedelta(days=1)

        # Store should be open for at least 1 hour and max 24 hours
        duration = close_dt - open_dt
        return timedelta(hours=1) <= duration <= timedelta(hours=24)
    except ValueError:
        return False


# ================== DATE & TIME UTILITIES ==================


def get_current_utc() -> datetime:
    """Get current UTC datetime"""
    return datetime.now(timezone.utc)


def format_datetime(dt: datetime, format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Format datetime to string"""
    return dt.strftime(format_str) if dt else ""


def parse_datetime(
    date_str: str, format_str: str = "%Y-%m-%d %H:%M:%S"
) -> Optional[datetime]:
    """Parse string to datetime"""
    try:
        return datetime.strptime(date_str, format_str)
    except (ValueError, TypeError):
        return None


def is_business_hours(current_time: datetime, open_time: str, close_time: str) -> bool:
    """Check if current time is within business hours"""
    try:
        current_time_only = current_time.time()
        open_dt = datetime.strptime(open_time, "%H:%M").time()
        close_dt = datetime.strptime(close_time, "%H:%M").time()

        # Handle overnight hours
        if close_dt < open_dt:
            return current_time_only >= open_dt or current_time_only <= close_dt
        else:
            return open_dt <= current_time_only <= close_dt
    except ValueError:
        return False


def get_shift_hours(shift_type: str) -> Tuple[str, str]:
    """Get start and end times for shift types"""
    shift_hours = {
        EmployeeConstants.SHIFT_TYPE_MORNING: ("06:00", "14:00"),
        EmployeeConstants.SHIFT_TYPE_AFTERNOON: ("14:00", "22:00"),
        EmployeeConstants.SHIFT_TYPE_EVENING: ("22:00", "06:00"),
    }
    return shift_hours.get(shift_type, ("09:00", "17:00"))


def calculate_age(birth_date: datetime) -> int:
    """Calculate age from birth date"""
    today = datetime.now().date()
    birth = birth_date.date() if isinstance(birth_date, datetime) else birth_date
    return (
        today.year - birth.year - ((today.month, today.day) < (birth.month, birth.day))
    )


def get_week_boundaries(date: datetime = None) -> Tuple[datetime, datetime]:
    """Get start and end of week for given date"""
    if date is None:
        date = datetime.now()

    # Get Monday of the week
    start_of_week = date - timedelta(days=date.weekday())
    start_of_week = start_of_week.replace(hour=0, minute=0, second=0, microsecond=0)

    # Get Sunday of the week
    end_of_week = start_of_week + timedelta(days=6, hours=23, minutes=59, seconds=59)

    return start_of_week, end_of_week


# ================== FINANCIAL UTILITIES ==================


def format_currency(amount: Union[float, Decimal], currency: str = "INR") -> str:
    """Format amount as currency (default INR for India)"""
    if amount is None:
        return f"0.00 {currency}"

    # Convert to Decimal for precision
    decimal_amount = Decimal(str(amount)).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_UP
    )

    # Indian number formatting (lakhs, crores)
    if currency == "INR":
        return format_inr_currency(decimal_amount)
    else:
        return f"{decimal_amount:,.2f} {currency}"


def format_inr_currency(amount: Decimal) -> str:
    """Format amount in Indian Rupee format with lakhs/crores"""
    amount_str = f"{amount:,.2f}"

    # Convert to Indian numbering system
    if amount >= 10000000:  # 1 crore
        crores = amount / 10000000
        return f"₹{crores:.2f} Cr"
    elif amount >= 100000:  # 1 lakh
        lakhs = amount / 100000
        return f"₹{lakhs:.2f} L"
    else:
        return f"₹{amount_str}"


def calculate_tax(
    subtotal: Union[float, Decimal], tax_rate: Union[float, Decimal]
) -> Decimal:
    """Calculate tax amount"""
    subtotal_decimal = Decimal(str(subtotal))
    tax_rate_decimal = Decimal(str(tax_rate))

    tax_amount = subtotal_decimal * tax_rate_decimal
    return tax_amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def calculate_discount(
    original_price: Union[float, Decimal], discount_percent: Union[float, Decimal]
) -> Decimal:
    """Calculate discount amount"""
    original_decimal = Decimal(str(original_price))
    discount_decimal = Decimal(str(discount_percent)) / 100

    discount_amount = original_decimal * discount_decimal
    return discount_amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def calculate_loyalty_points(amount: Union[float, Decimal], tier: str) -> int:
    """Calculate loyalty points earned"""
    earning_rates = CustomerConstants.LOYALTY_POINTS_EARNING_RATE
    rate = earning_rates.get(tier, 1)

    amount_decimal = Decimal(str(amount))
    points = amount_decimal * Decimal(str(rate))
    return int(points)


# ================== INVENTORY UTILITIES ==================


def calculate_reorder_point(
    daily_usage: int, lead_time_days: int, safety_stock: int = 0
) -> int:
    """Calculate inventory reorder point"""
    return (daily_usage * lead_time_days) + safety_stock


def categorize_stock_level(
    current_stock: int, low_threshold: int, critical_threshold: int
) -> str:
    """Categorize stock level status"""
    if current_stock <= critical_threshold:
        return "critical"
    elif current_stock <= low_threshold:
        return "low"
    elif current_stock >= BusinessConstants.OVERSTOCK_THRESHOLD:
        return "overstock"
    else:
        return "normal"


def calculate_inventory_turnover(
    cost_of_goods_sold: Decimal, average_inventory: Decimal
) -> Decimal:
    """Calculate inventory turnover ratio"""
    if average_inventory == 0:
        return Decimal("0")

    turnover = cost_of_goods_sold / average_inventory
    return turnover.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


# ================== PAGINATION UTILITIES ==================


def paginate_query(page: int, page_size: int, total_items: int) -> Dict[str, Any]:
    """Calculate pagination parameters"""
    # Validate inputs
    page = max(1, page)
    page_size = min(max(1, page_size), BusinessConstants.MAX_PAGE_SIZE)

    # Calculate pagination values
    total_pages = (total_items + page_size - 1) // page_size
    offset = (page - 1) * page_size

    # Determine if there are previous/next pages
    has_previous = page > 1
    has_next = page < total_pages

    return {
        "page": page,
        "page_size": page_size,
        "total_items": total_items,
        "total_pages": total_pages,
        "offset": offset,
        "has_previous": has_previous,
        "has_next": has_next,
        "previous_page": page - 1 if has_previous else None,
        "next_page": page + 1 if has_next else None,
    }


# ================== SECURITY UTILITIES ==================


def generate_secure_token(length: int = 32) -> str:
    """Generate cryptographically secure random token"""
    return secrets.token_urlsafe(length)


def hash_data(data: str, salt: str = None) -> str:
    """Hash data with optional salt"""
    if salt is None:
        salt = secrets.token_hex(16)

    hash_input = f"{data}{salt}".encode("utf-8")
    hash_object = hashlib.sha256(hash_input)
    return hash_object.hexdigest()


def mask_sensitive_data(data: str, mask_char: str = "*", visible_chars: int = 4) -> str:
    """Mask sensitive data (e.g., credit card numbers, SSN)"""
    if not data or len(data) <= visible_chars:
        return data

    visible_part = data[-visible_chars:]
    masked_part = mask_char * (len(data) - visible_chars)
    return f"{masked_part}{visible_part}"


def generate_correlation_id() -> str:
    """Generate correlation ID for request tracing"""
    return str(uuid.uuid4())


# ================== DATA TRANSFORMATION UTILITIES ==================


def flatten_dict(
    d: Dict[str, Any], parent_key: str = "", sep: str = "."
) -> Dict[str, Any]:
    """Flatten nested dictionary"""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def unflatten_dict(d: Dict[str, Any], sep: str = ".") -> Dict[str, Any]:
    """Unflatten dictionary with dot notation keys"""
    result = {}
    for key, value in d.items():
        keys = key.split(sep)
        current = result
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        current[keys[-1]] = value
    return result


def deep_merge_dicts(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """Deep merge two dictionaries"""
    result = dict1.copy()
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge_dicts(result[key], value)
        else:
            result[key] = value
    return result


def safe_json_loads(json_str: str, default: Any = None) -> Any:
    """Safely parse JSON string"""
    try:
        return json.loads(json_str)
    except (json.JSONDecodeError, TypeError):
        return default


def safe_json_dumps(obj: Any, default: str = "{}") -> str:
    """Safely serialize object to JSON"""
    try:
        return json.dumps(obj, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        return default


# ================== FILE UTILITIES ==================


def get_file_extension(filename: str) -> str:
    """Get file extension from filename"""
    return filename.split(".")[-1].lower() if "." in filename else ""


def is_allowed_file_type(filename: str, allowed_extensions: List[str]) -> bool:
    """Check if file type is allowed"""
    extension = f".{get_file_extension(filename)}"
    return extension in allowed_extensions


def format_file_size(size_bytes: int) -> str:
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0 B"

    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    size = float(size_bytes)

    while size >= 1024.0 and i < len(size_names) - 1:
        size /= 1024.0
        i += 1

    return f"{size:.1f} {size_names[i]}"


# ================== SEARCH & FILTER UTILITIES ==================


def build_search_query(search_term: str, fields: List[str]) -> Dict[str, Any]:
    """Build MongoDB search query for multiple fields"""
    if not search_term:
        return {}

    # Escape special regex characters
    escaped_term = re.escape(search_term)

    # Create case-insensitive regex pattern
    regex_pattern = {"$regex": escaped_term, "$options": "i"}

    # Build OR query for all specified fields
    or_conditions = [{field: regex_pattern} for field in fields]

    return {"$or": or_conditions}


def apply_filters(
    base_query: Dict[str, Any], filters: Dict[str, Any]
) -> Dict[str, Any]:
    """Apply filters to MongoDB query"""
    query = base_query.copy()

    for field, value in filters.items():
        if value is not None and value != "":
            # Handle range filters (e.g., price_min, price_max)
            if field.endswith("_min"):
                base_field = field[:-4]
                query[base_field] = query.get(base_field, {})
                query[base_field]["$gte"] = value
            elif field.endswith("_max"):
                base_field = field[:-4]
                query[base_field] = query.get(base_field, {})
                query[base_field]["$lte"] = value
            # Handle array filters (e.g., categories)
            elif isinstance(value, list):
                query[field] = {"$in": value}
            # Handle exact matches
            else:
                query[field] = value

    return query


# ================== BUSINESS LOGIC HELPERS ==================


def calculate_shift_duration(start_time: str, end_time: str) -> float:
    """Calculate shift duration in hours"""
    try:
        start = datetime.strptime(start_time, "%H:%M")
        end = datetime.strptime(end_time, "%H:%M")

        # Handle overnight shifts
        if end < start:
            end += timedelta(days=1)

        duration = end - start
        return duration.total_seconds() / 3600  # Convert to hours
    except ValueError:
        return 0.0


def is_peak_hours(
    current_time: datetime, peak_start: str = "11:00", peak_end: str = "14:00"
) -> bool:
    """Check if current time is during peak business hours"""
    return is_business_hours(current_time, peak_start, peak_end)


def calculate_commission(
    sales_amount: Decimal, commission_rate: Decimal, tier: str = "basic"
) -> Decimal:
    """Calculate sales commission based on amount and tier"""
    base_commission = sales_amount * commission_rate

    # Tier-based multipliers
    tier_multipliers = {
        "basic": Decimal("1.0"),
        "silver": Decimal("1.1"),
        "gold": Decimal("1.2"),
        "platinum": Decimal("1.3"),
    }

    multiplier = tier_multipliers.get(tier, Decimal("1.0"))
    final_commission = base_commission * multiplier

    return final_commission.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


# Export all helper functions
__all__ = [
    # String utilities
    "generate_id",
    "generate_tenant_subdomain",
    "generate_sku",
    "generate_employee_id",
    "sanitize_string",
    "slugify",
    # Validation utilities
    "validate_email",
    "validate_phone",
    "validate_sku",
    "validate_barcode",
    "validate_store_hours",
    # Date & time utilities
    "get_current_utc",
    "format_datetime",
    "parse_datetime",
    "is_business_hours",
    "get_shift_hours",
    "calculate_age",
    "get_week_boundaries",
    # Financial utilities
    "format_currency",
    "calculate_tax",
    "calculate_discount",
    "calculate_loyalty_points",
    # Inventory utilities
    "calculate_reorder_point",
    "categorize_stock_level",
    "calculate_inventory_turnover",
    # Pagination utilities
    "paginate_query",
    # Security utilities
    "generate_secure_token",
    "hash_data",
    "mask_sensitive_data",
    "generate_correlation_id",
    # Data transformation utilities
    "flatten_dict",
    "unflatten_dict",
    "deep_merge_dicts",
    "safe_json_loads",
    "safe_json_dumps",
    # File utilities
    "get_file_extension",
    "is_allowed_file_type",
    "format_file_size",
    # Search & filter utilities
    "build_search_query",
    "apply_filters",
    # Business logic helpers
    "calculate_shift_duration",
    "is_peak_hours",
    "calculate_commission",
]


def validate_pan(pan: str) -> bool:
    """Validate Indian PAN (Permanent Account Number)"""
    if not pan or len(pan) != 10:
        return False

    # PAN format: 5 letters + 4 digits + 1 letter
    pan_pattern = r"^[A-Z]{5}[0-9]{4}[A-Z]{1}$"
    return re.match(pan_pattern, pan.upper()) is not None


def validate_sku(sku: str) -> bool:
    """Validate SKU format"""
    if not sku:
        return False
    return (
        re.match(RegexPatterns.OBJECTID, sku) is not None
        or re.match(ProductConstants.SKU_PATTERN, sku) is not None
    )


def validate_barcode(barcode: str, barcode_type: str = "UPC") -> bool:
    """Validate barcode format based on type"""
    if not barcode:
        return False

    patterns = ProductConstants.BARCODE_PATTERNS
    if barcode_type not in patterns:
        return False

    return re.match(patterns[barcode_type], barcode) is not None


def validate_store_hours(open_time: str, close_time: str) -> bool:
    """Validate store operating hours"""
    try:
        open_dt = datetime.strptime(open_time, "%H:%M")
        close_dt = datetime.strptime(close_time, "%H:%M")

        # Handle overnight hours (e.g., 22:00 to 06:00)
        if close_dt < open_dt:
            close_dt += timedelta(days=1)

        # Store should be open for at least 1 hour and max 24 hours
        duration = close_dt - open_dt
        return timedelta(hours=1) <= duration <= timedelta(hours=24)
    except ValueError:
        return False


# ================== DATE & TIME UTILITIES ==================


def get_current_utc() -> datetime:
    """Get current UTC datetime"""
    return datetime.now(timezone.utc)


def format_datetime(dt: datetime, format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Format datetime to string"""
    return dt.strftime(format_str) if dt else ""


def parse_datetime(
    date_str: str, format_str: str = "%Y-%m-%d %H:%M:%S"
) -> Optional[datetime]:
    """Parse string to datetime"""
    try:
        return datetime.strptime(date_str, format_str)
    except (ValueError, TypeError):
        return None


def is_business_hours(current_time: datetime, open_time: str, close_time: str) -> bool:
    """Check if current time is within business hours"""
    try:
        current_time_only = current_time.time()
        open_dt = datetime.strptime(open_time, "%H:%M").time()
        close_dt = datetime.strptime(close_time, "%H:%M").time()

        # Handle overnight hours
        if close_dt < open_dt:
            return current_time_only >= open_dt or current_time_only <= close_dt
        else:
            return open_dt <= current_time_only <= close_dt
    except ValueError:
        return False


def get_shift_hours(shift_type: str) -> Tuple[str, str]:
    """Get start and end times for shift types"""
    shift_hours = {
        EmployeeConstants.SHIFT_TYPE_MORNING: ("06:00", "14:00"),
        EmployeeConstants.SHIFT_TYPE_AFTERNOON: ("14:00", "22:00"),
        EmployeeConstants.SHIFT_TYPE_EVENING: ("22:00", "06:00"),
    }
    return shift_hours.get(shift_type, ("09:00", "17:00"))


def calculate_age(birth_date: datetime) -> int:
    """Calculate age from birth date"""
    today = datetime.now().date()
    birth = birth_date.date() if isinstance(birth_date, datetime) else birth_date
    return (
        today.year - birth.year - ((today.month, today.day) < (birth.month, birth.day))
    )


def get_week_boundaries(date: datetime = None) -> Tuple[datetime, datetime]:
    """Get start and end of week for given date"""
    if date is None:
        date = datetime.now()

    # Get Monday of the week
    start_of_week = date - timedelta(days=date.weekday())
    start_of_week = start_of_week.replace(hour=0, minute=0, second=0, microsecond=0)

    # Get Sunday of the week
    end_of_week = start_of_week + timedelta(days=6, hours=23, minutes=59, seconds=59)

    return start_of_week, end_of_week


# ================== FINANCIAL UTILITIES ==================


def format_currency(amount: Union[float, Decimal], currency: str = "INR") -> str:
    """Format amount as currency (default INR for India)"""
    if amount is None:
        return f"0.00 {currency}"

    # Convert to Decimal for precision
    decimal_amount = Decimal(str(amount)).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_UP
    )

    # Indian number formatting (lakhs, crores)
    if currency == "INR":
        return format_inr_currency(decimal_amount)
    else:
        return f"{decimal_amount:,.2f} {currency}"


def format_inr_currency(amount: Decimal) -> str:
    """Format amount in Indian Rupee format with lakhs/crores"""
    amount_str = f"{amount:,.2f}"

    # Convert to Indian numbering system
    if amount >= 10000000:  # 1 crore
        crores = amount / 10000000
        return f"₹{crores:.2f} Cr"
    elif amount >= 100000:  # 1 lakh
        lakhs = amount / 100000
        return f"₹{lakhs:.2f} L"
    else:
        return f"₹{amount_str}"


def calculate_tax(
    subtotal: Union[float, Decimal], tax_rate: Union[float, Decimal]
) -> Decimal:
    """Calculate tax amount"""
    subtotal_decimal = Decimal(str(subtotal))
    tax_rate_decimal = Decimal(str(tax_rate))

    tax_amount = subtotal_decimal * tax_rate_decimal
    return tax_amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def calculate_discount(
    original_price: Union[float, Decimal], discount_percent: Union[float, Decimal]
) -> Decimal:
    """Calculate discount amount"""
    original_decimal = Decimal(str(original_price))
    discount_decimal = Decimal(str(discount_percent)) / 100

    discount_amount = original_decimal * discount_decimal
    return discount_amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def calculate_loyalty_points(amount: Union[float, Decimal], tier: str) -> int:
    """Calculate loyalty points earned"""
    earning_rates = CustomerConstants.LOYALTY_POINTS_EARNING_RATE
    rate = earning_rates.get(tier, 1)

    amount_decimal = Decimal(str(amount))
    points = amount_decimal * Decimal(str(rate))
    return int(points)


# ================== INVENTORY UTILITIES ==================


def calculate_reorder_point(
    daily_usage: int, lead_time_days: int, safety_stock: int = 0
) -> int:
    """Calculate inventory reorder point"""
    return (daily_usage * lead_time_days) + safety_stock


def categorize_stock_level(
    current_stock: int, low_threshold: int, critical_threshold: int
) -> str:
    """Categorize stock level status"""
    if current_stock <= critical_threshold:
        return "critical"
    elif current_stock <= low_threshold:
        return "low"
    elif current_stock >= BusinessConstants.OVERSTOCK_THRESHOLD:
        return "overstock"
    else:
        return "normal"


def calculate_inventory_turnover(
    cost_of_goods_sold: Decimal, average_inventory: Decimal
) -> Decimal:
    """Calculate inventory turnover ratio"""
    if average_inventory == 0:
        return Decimal("0")

    turnover = cost_of_goods_sold / average_inventory
    return turnover.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


# ================== PAGINATION UTILITIES ==================


def paginate_query(page: int, page_size: int, total_items: int) -> Dict[str, Any]:
    """Calculate pagination parameters"""
    # Validate inputs
    page = max(1, page)
    page_size = min(max(1, page_size), BusinessConstants.MAX_PAGE_SIZE)

    # Calculate pagination values
    total_pages = (total_items + page_size - 1) // page_size
    offset = (page - 1) * page_size

    # Determine if there are previous/next pages
    has_previous = page > 1
    has_next = page < total_pages

    return {
        "page": page,
        "page_size": page_size,
        "total_items": total_items,
        "total_pages": total_pages,
        "offset": offset,
        "has_previous": has_previous,
        "has_next": has_next,
        "previous_page": page - 1 if has_previous else None,
        "next_page": page + 1 if has_next else None,
    }


# ================== SECURITY UTILITIES ==================


def generate_secure_token(length: int = 32) -> str:
    """Generate cryptographically secure random token"""
    return secrets.token_urlsafe(length)


def hash_data(data: str, salt: str = None) -> str:
    """Hash data with optional salt"""
    if salt is None:
        salt = secrets.token_hex(16)

    hash_input = f"{data}{salt}".encode("utf-8")
    hash_object = hashlib.sha256(hash_input)
    return hash_object.hexdigest()


def mask_sensitive_data(data: str, mask_char: str = "*", visible_chars: int = 4) -> str:
    """Mask sensitive data (e.g., credit card numbers, SSN)"""
    if not data or len(data) <= visible_chars:
        return data

    visible_part = data[-visible_chars:]
    masked_part = mask_char * (len(data) - visible_chars)
    return f"{masked_part}{visible_part}"


def generate_correlation_id() -> str:
    """Generate correlation ID for request tracing"""
    return str(uuid.uuid4())


# ================== DATA TRANSFORMATION UTILITIES ==================


def flatten_dict(
    d: Dict[str, Any], parent_key: str = "", sep: str = "."
) -> Dict[str, Any]:
    """Flatten nested dictionary"""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def unflatten_dict(d: Dict[str, Any], sep: str = ".") -> Dict[str, Any]:
    """Unflatten dictionary with dot notation keys"""
    result = {}
    for key, value in d.items():
        keys = key.split(sep)
        current = result
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        current[keys[-1]] = value
    return result


def deep_merge_dicts(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """Deep merge two dictionaries"""
    result = dict1.copy()
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge_dicts(result[key], value)
        else:
            result[key] = value
    return result


def safe_json_loads(json_str: str, default: Any = None) -> Any:
    """Safely parse JSON string"""
    try:
        return json.loads(json_str)
    except (json.JSONDecodeError, TypeError):
        return default


def safe_json_dumps(obj: Any, default: str = "{}") -> str:
    """Safely serialize object to JSON"""
    try:
        return json.dumps(obj, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        return default


# ================== FILE UTILITIES ==================


def get_file_extension(filename: str) -> str:
    """Get file extension from filename"""
    return filename.split(".")[-1].lower() if "." in filename else ""


def is_allowed_file_type(filename: str, allowed_extensions: List[str]) -> bool:
    """Check if file type is allowed"""
    extension = f".{get_file_extension(filename)}"
    return extension in allowed_extensions


def format_file_size(size_bytes: int) -> str:
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0 B"

    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    size = float(size_bytes)

    while size >= 1024.0 and i < len(size_names) - 1:
        size /= 1024.0
        i += 1

    return f"{size:.1f} {size_names[i]}"


# ================== SEARCH & FILTER UTILITIES ==================


def build_search_query(search_term: str, fields: List[str]) -> Dict[str, Any]:
    """Build MongoDB search query for multiple fields"""
    if not search_term:
        return {}

    # Escape special regex characters
    escaped_term = re.escape(search_term)

    # Create case-insensitive regex pattern
    regex_pattern = {"$regex": escaped_term, "$options": "i"}

    # Build OR query for all specified fields
    or_conditions = [{field: regex_pattern} for field in fields]

    return {"$or": or_conditions}


def apply_filters(
    base_query: Dict[str, Any], filters: Dict[str, Any]
) -> Dict[str, Any]:
    """Apply filters to MongoDB query"""
    query = base_query.copy()

    for field, value in filters.items():
        if value is not None and value != "":
            # Handle range filters (e.g., price_min, price_max)
            if field.endswith("_min"):
                base_field = field[:-4]
                query[base_field] = query.get(base_field, {})
                query[base_field]["$gte"] = value
            elif field.endswith("_max"):
                base_field = field[:-4]
                query[base_field] = query.get(base_field, {})
                query[base_field]["$lte"] = value
            # Handle array filters (e.g., categories)
            elif isinstance(value, list):
                query[field] = {"$in": value}
            # Handle exact matches
            else:
                query[field] = value

    return query


# ================== BUSINESS LOGIC HELPERS ==================


def calculate_shift_duration(start_time: str, end_time: str) -> float:
    """Calculate shift duration in hours"""
    try:
        start = datetime.strptime(start_time, "%H:%M")
        end = datetime.strptime(end_time, "%H:%M")

        # Handle overnight shifts
        if end < start:
            end += timedelta(days=1)

        duration = end - start
        return duration.total_seconds() / 3600  # Convert to hours
    except ValueError:
        return 0.0


def is_peak_hours(
    current_time: datetime, peak_start: str = "11:00", peak_end: str = "14:00"
) -> bool:
    """Check if current time is during peak business hours"""
    return is_business_hours(current_time, peak_start, peak_end)


def calculate_commission(
    sales_amount: Decimal, commission_rate: Decimal, tier: str = "basic"
) -> Decimal:
    """Calculate sales commission based on amount and tier"""
    base_commission = sales_amount * commission_rate

    # Tier-based multipliers
    tier_multipliers = {
        "basic": Decimal("1.0"),
        "silver": Decimal("1.1"),
        "gold": Decimal("1.2"),
        "platinum": Decimal("1.3"),
    }

    multiplier = tier_multipliers.get(tier, Decimal("1.0"))
    final_commission = base_commission * multiplier

    return final_commission.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


# Export all helper functions
__all__ = [
    # String utilities
    "generate_id",
    "generate_tenant_subdomain",
    "generate_sku",
    "generate_employee_id",
    "sanitize_string",
    "slugify",
    # Validation utilities
    "validate_email",
    "validate_phone",
    "validate_sku",
    "validate_barcode",
    "validate_store_hours",
    # Date & time utilities
    "get_current_utc",
    "format_datetime",
    "parse_datetime",
    "is_business_hours",
    "get_shift_hours",
    "calculate_age",
    "get_week_boundaries",
    # Financial utilities
    "format_currency",
    "calculate_tax",
    "calculate_discount",
    "calculate_loyalty_points",
    # Inventory utilities
    "calculate_reorder_point",
    "categorize_stock_level",
    "calculate_inventory_turnover",
    # Pagination utilities
    "paginate_query",
    # Security utilities
    "generate_secure_token",
    "hash_data",
    "mask_sensitive_data",
    "generate_correlation_id",
    # Data transformation utilities
    "flatten_dict",
    "unflatten_dict",
    "deep_merge_dicts",
    "safe_json_loads",
    "safe_json_dumps",
    # File utilities
    "get_file_extension",
    "is_allowed_file_type",
    "format_file_size",
    # Search & filter utilities
    "build_search_query",
    "apply_filters",
    # Business logic helpers
    "calculate_shift_duration",
    "is_peak_hours",
    "calculate_commission",
]


def validate_aadhaar(aadhaar: str) -> bool:
    """Validate Indian Aadhaar number"""
    if not aadhaar:
        return False

    # Remove spaces and hyphens
    cleaned = re.sub(r"[\s-]", "", aadhaar)

    # Should be 12 digits
    cleaned = re.sub(r"[^\d]", "", aadhaar)
    if not re.match(r"^\d{12}$", cleaned):
        return False

    return True


def validate_sku(sku: str) -> bool:
    """Validate SKU format"""
    if not sku:
        return False
    return (
        re.match(RegexPatterns.OBJECTID, sku) is not None
        or re.match(ProductConstants.SKU_PATTERN, sku) is not None
    )


def validate_barcode(barcode: str, barcode_type: str = "UPC") -> bool:
    """Validate barcode format based on type"""
    if not barcode:
        return False

    patterns = ProductConstants.BARCODE_PATTERNS
    if barcode_type not in patterns:
        return False

    return re.match(patterns[barcode_type], barcode) is not None


def validate_store_hours(open_time: str, close_time: str) -> bool:
    """Validate store operating hours"""
    try:
        open_dt = datetime.strptime(open_time, "%H:%M")
        close_dt = datetime.strptime(close_time, "%H:%M")

        # Handle overnight hours (e.g., 22:00 to 06:00)
        if close_dt < open_dt:
            close_dt += timedelta(days=1)

        # Store should be open for at least 1 hour and max 24 hours
        duration = close_dt - open_dt
        return timedelta(hours=1) <= duration <= timedelta(hours=24)
    except ValueError:
        return False


# ================== DATE & TIME UTILITIES ==================


def get_current_utc() -> datetime:
    """Get current UTC datetime"""
    return datetime.now(timezone.utc)


def format_datetime(dt: datetime, format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Format datetime to string"""
    return dt.strftime(format_str) if dt else ""


def parse_datetime(
    date_str: str, format_str: str = "%Y-%m-%d %H:%M:%S"
) -> Optional[datetime]:
    """Parse string to datetime"""
    try:
        return datetime.strptime(date_str, format_str)
    except (ValueError, TypeError):
        return None


def is_business_hours(current_time: datetime, open_time: str, close_time: str) -> bool:
    """Check if current time is within business hours"""
    try:
        current_time_only = current_time.time()
        open_dt = datetime.strptime(open_time, "%H:%M").time()
        close_dt = datetime.strptime(close_time, "%H:%M").time()

        # Handle overnight hours
        if close_dt < open_dt:
            return current_time_only >= open_dt or current_time_only <= close_dt
        else:
            return open_dt <= current_time_only <= close_dt
    except ValueError:
        return False


def get_shift_hours(shift_type: str) -> Tuple[str, str]:
    """Get start and end times for shift types"""
    shift_hours = {
        EmployeeConstants.SHIFT_TYPE_MORNING: ("06:00", "14:00"),
        EmployeeConstants.SHIFT_TYPE_AFTERNOON: ("14:00", "22:00"),
        EmployeeConstants.SHIFT_TYPE_EVENING: ("22:00", "06:00"),
    }
    return shift_hours.get(shift_type, ("09:00", "17:00"))


def calculate_age(birth_date: datetime) -> int:
    """Calculate age from birth date"""
    today = datetime.now().date()
    birth = birth_date.date() if isinstance(birth_date, datetime) else birth_date
    return (
        today.year - birth.year - ((today.month, today.day) < (birth.month, birth.day))
    )


def get_week_boundaries(date: datetime = None) -> Tuple[datetime, datetime]:
    """Get start and end of week for given date"""
    if date is None:
        date = datetime.now()

    # Get Monday of the week
    start_of_week = date - timedelta(days=date.weekday())
    start_of_week = start_of_week.replace(hour=0, minute=0, second=0, microsecond=0)

    # Get Sunday of the week
    end_of_week = start_of_week + timedelta(days=6, hours=23, minutes=59, seconds=59)

    return start_of_week, end_of_week


# ================== FINANCIAL UTILITIES ==================


def format_currency(amount: Union[float, Decimal], currency: str = "INR") -> str:
    """Format amount as currency (default INR for India)"""
    if amount is None:
        return f"0.00 {currency}"

    # Convert to Decimal for precision
    decimal_amount = Decimal(str(amount)).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_UP
    )

    # Indian number formatting (lakhs, crores)
    if currency == "INR":
        return format_inr_currency(decimal_amount)
    else:
        return f"{decimal_amount:,.2f} {currency}"


def format_inr_currency(amount: Decimal) -> str:
    """Format amount in Indian Rupee format with lakhs/crores"""
    amount_str = f"{amount:,.2f}"

    # Convert to Indian numbering system
    if amount >= 10000000:  # 1 crore
        crores = amount / 10000000
        return f"₹{crores:.2f} Cr"
    elif amount >= 100000:  # 1 lakh
        lakhs = amount / 100000
        return f"₹{lakhs:.2f} L"
    else:
        return f"₹{amount_str}"


def calculate_tax(
    subtotal: Union[float, Decimal], tax_rate: Union[float, Decimal]
) -> Decimal:
    """Calculate tax amount"""
    subtotal_decimal = Decimal(str(subtotal))
    tax_rate_decimal = Decimal(str(tax_rate))

    tax_amount = subtotal_decimal * tax_rate_decimal
    return tax_amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def calculate_discount(
    original_price: Union[float, Decimal], discount_percent: Union[float, Decimal]
) -> Decimal:
    """Calculate discount amount"""
    original_decimal = Decimal(str(original_price))
    discount_decimal = Decimal(str(discount_percent)) / 100

    discount_amount = original_decimal * discount_decimal
    return discount_amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def calculate_loyalty_points(amount: Union[float, Decimal], tier: str) -> int:
    """Calculate loyalty points earned"""
    earning_rates = CustomerConstants.LOYALTY_POINTS_EARNING_RATE
    rate = earning_rates.get(tier, 1)

    amount_decimal = Decimal(str(amount))
    points = amount_decimal * Decimal(str(rate))
    return int(points)


# ================== INVENTORY UTILITIES ==================


def calculate_reorder_point(
    daily_usage: int, lead_time_days: int, safety_stock: int = 0
) -> int:
    """Calculate inventory reorder point"""
    return (daily_usage * lead_time_days) + safety_stock


def categorize_stock_level(
    current_stock: int, low_threshold: int, critical_threshold: int
) -> str:
    """Categorize stock level status"""
    if current_stock <= critical_threshold:
        return "critical"
    elif current_stock <= low_threshold:
        return "low"
    elif current_stock >= BusinessConstants.OVERSTOCK_THRESHOLD:
        return "overstock"
    else:
        return "normal"


def calculate_inventory_turnover(
    cost_of_goods_sold: Decimal, average_inventory: Decimal
) -> Decimal:
    """Calculate inventory turnover ratio"""
    if average_inventory == 0:
        return Decimal("0")

    turnover = cost_of_goods_sold / average_inventory
    return turnover.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


# ================== PAGINATION UTILITIES ==================


def paginate_query(page: int, page_size: int, total_items: int) -> Dict[str, Any]:
    """Calculate pagination parameters"""
    # Validate inputs
    page = max(1, page)
    page_size = min(max(1, page_size), BusinessConstants.MAX_PAGE_SIZE)

    # Calculate pagination values
    total_pages = (total_items + page_size - 1) // page_size
    offset = (page - 1) * page_size

    # Determine if there are previous/next pages
    has_previous = page > 1
    has_next = page < total_pages

    return {
        "page": page,
        "page_size": page_size,
        "total_items": total_items,
        "total_pages": total_pages,
        "offset": offset,
        "has_previous": has_previous,
        "has_next": has_next,
        "previous_page": page - 1 if has_previous else None,
        "next_page": page + 1 if has_next else None,
    }


# ================== SECURITY UTILITIES ==================


def generate_secure_token(length: int = 32) -> str:
    """Generate cryptographically secure random token"""
    return secrets.token_urlsafe(length)


def hash_data(data: str, salt: str = None) -> str:
    """Hash data with optional salt"""
    if salt is None:
        salt = secrets.token_hex(16)

    hash_input = f"{data}{salt}".encode("utf-8")
    hash_object = hashlib.sha256(hash_input)
    return hash_object.hexdigest()


def mask_sensitive_data(data: str, mask_char: str = "*", visible_chars: int = 4) -> str:
    """Mask sensitive data (e.g., credit card numbers, SSN)"""
    if not data or len(data) <= visible_chars:
        return data

    visible_part = data[-visible_chars:]
    masked_part = mask_char * (len(data) - visible_chars)
    return f"{masked_part}{visible_part}"


def generate_correlation_id() -> str:
    """Generate correlation ID for request tracing"""
    return str(uuid.uuid4())


# ================== DATA TRANSFORMATION UTILITIES ==================


def flatten_dict(
    d: Dict[str, Any], parent_key: str = "", sep: str = "."
) -> Dict[str, Any]:
    """Flatten nested dictionary"""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def unflatten_dict(d: Dict[str, Any], sep: str = ".") -> Dict[str, Any]:
    """Unflatten dictionary with dot notation keys"""
    result = {}
    for key, value in d.items():
        keys = key.split(sep)
        current = result
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        current[keys[-1]] = value
    return result


def deep_merge_dicts(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """Deep merge two dictionaries"""
    result = dict1.copy()
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge_dicts(result[key], value)
        else:
            result[key] = value
    return result


def safe_json_loads(json_str: str, default: Any = None) -> Any:
    """Safely parse JSON string"""
    try:
        return json.loads(json_str)
    except (json.JSONDecodeError, TypeError):
        return default


def safe_json_dumps(obj: Any, default: str = "{}") -> str:
    """Safely serialize object to JSON"""
    try:
        return json.dumps(obj, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        return default


# ================== FILE UTILITIES ==================


def get_file_extension(filename: str) -> str:
    """Get file extension from filename"""
    return filename.split(".")[-1].lower() if "." in filename else ""


def is_allowed_file_type(filename: str, allowed_extensions: List[str]) -> bool:
    """Check if file type is allowed"""
    extension = f".{get_file_extension(filename)}"
    return extension in allowed_extensions


def format_file_size(size_bytes: int) -> str:
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0 B"

    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    size = float(size_bytes)

    while size >= 1024.0 and i < len(size_names) - 1:
        size /= 1024.0
        i += 1

    return f"{size:.1f} {size_names[i]}"


# ================== SEARCH & FILTER UTILITIES ==================


def build_search_query(search_term: str, fields: List[str]) -> Dict[str, Any]:
    """Build MongoDB search query for multiple fields"""
    if not search_term:
        return {}

    # Escape special regex characters
    escaped_term = re.escape(search_term)

    # Create case-insensitive regex pattern
    regex_pattern = {"$regex": escaped_term, "$options": "i"}

    # Build OR query for all specified fields
    or_conditions = [{field: regex_pattern} for field in fields]

    return {"$or": or_conditions}


def apply_filters(
    base_query: Dict[str, Any], filters: Dict[str, Any]
) -> Dict[str, Any]:
    """Apply filters to MongoDB query"""
    query = base_query.copy()

    for field, value in filters.items():
        if value is not None and value != "":
            # Handle range filters (e.g., price_min, price_max)
            if field.endswith("_min"):
                base_field = field[:-4]
                query[base_field] = query.get(base_field, {})
                query[base_field]["$gte"] = value
            elif field.endswith("_max"):
                base_field = field[:-4]
                query[base_field] = query.get(base_field, {})
                query[base_field]["$lte"] = value
            # Handle array filters (e.g., categories)
            elif isinstance(value, list):
                query[field] = {"$in": value}
            # Handle exact matches
            else:
                query[field] = value

    return query


# ================== BUSINESS LOGIC HELPERS ==================


def calculate_shift_duration(start_time: str, end_time: str) -> float:
    """Calculate shift duration in hours"""
    try:
        start = datetime.strptime(start_time, "%H:%M")
        end = datetime.strptime(end_time, "%H:%M")

        # Handle overnight shifts
        if end < start:
            end += timedelta(days=1)

        duration = end - start
        return duration.total_seconds() / 3600  # Convert to hours
    except ValueError:
        return 0.0


def is_peak_hours(
    current_time: datetime, peak_start: str = "11:00", peak_end: str = "14:00"
) -> bool:
    """Check if current time is during peak business hours"""
    return is_business_hours(current_time, peak_start, peak_end)


def calculate_commission(
    sales_amount: Decimal, commission_rate: Decimal, tier: str = "basic"
) -> Decimal:
    """Calculate sales commission based on amount and tier"""
    base_commission = sales_amount * commission_rate

    # Tier-based multipliers
    tier_multipliers = {
        "basic": Decimal("1.0"),
        "silver": Decimal("1.1"),
        "gold": Decimal("1.2"),
        "platinum": Decimal("1.3"),
    }

    multiplier = tier_multipliers.get(tier, Decimal("1.0"))
    final_commission = base_commission * multiplier

    return final_commission.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


# Export all helper functions
__all__ = [
    # String utilities
    "generate_id",
    "generate_tenant_subdomain",
    "generate_sku",
    "generate_employee_id",
    "sanitize_string",
    "slugify",
    # Validation utilities
    "validate_email",
    "validate_phone",
    "validate_sku",
    "validate_barcode",
    "validate_store_hours",
    # Date & time utilities
    "get_current_utc",
    "format_datetime",
    "parse_datetime",
    "is_business_hours",
    "get_shift_hours",
    "calculate_age",
    "get_week_boundaries",
    # Financial utilities
    "format_currency",
    "calculate_tax",
    "calculate_discount",
    "calculate_loyalty_points",
    # Inventory utilities
    "calculate_reorder_point",
    "categorize_stock_level",
    "calculate_inventory_turnover",
    # Pagination utilities
    "paginate_query",
    # Security utilities
    "generate_secure_token",
    "hash_data",
    "mask_sensitive_data",
    "generate_correlation_id",
    # Data transformation utilities
    "flatten_dict",
    "unflatten_dict",
    "deep_merge_dicts",
    "safe_json_loads",
    "safe_json_dumps",
    # File utilities
    "get_file_extension",
    "is_allowed_file_type",
    "format_file_size",
    # Search & filter utilities
    "build_search_query",
    "apply_filters",
    # Business logic helpers
    "calculate_shift_duration",
    "is_peak_hours",
    "calculate_commission",
]


def validate_ifsc(ifsc: str) -> bool:
    """Validate Indian IFSC (Indian Financial System Code)"""
    if not ifsc or len(ifsc) != 11:
        return False

    # IFSC format: 4 letters bank code + 0 + 6 alphanumeric branch code
    ifsc_pattern = r"^[A-Z]{4}0[A-Z0-9]{6}$"
    return re.match(ifsc_pattern, ifsc.upper()) is not None


def validate_sku(sku: str) -> bool:
    """Validate SKU format"""
    if not sku:
        return False
    return (
        re.match(RegexPatterns.OBJECTID, sku) is not None
        or re.match(ProductConstants.SKU_PATTERN, sku) is not None
    )


def validate_barcode(barcode: str, barcode_type: str = "UPC") -> bool:
    """Validate barcode format based on type"""
    if not barcode:
        return False

    patterns = ProductConstants.BARCODE_PATTERNS
    if barcode_type not in patterns:
        return False

    return re.match(patterns[barcode_type], barcode) is not None


def validate_store_hours(open_time: str, close_time: str) -> bool:
    """Validate store operating hours"""
    try:
        open_dt = datetime.strptime(open_time, "%H:%M")
        close_dt = datetime.strptime(close_time, "%H:%M")

        # Handle overnight hours (e.g., 22:00 to 06:00)
        if close_dt < open_dt:
            close_dt += timedelta(days=1)

        # Store should be open for at least 1 hour and max 24 hours
        duration = close_dt - open_dt
        return timedelta(hours=1) <= duration <= timedelta(hours=24)
    except ValueError:
        return False


# ================== DATE & TIME UTILITIES ==================


def get_current_utc() -> datetime:
    """Get current UTC datetime"""
    return datetime.now(timezone.utc)


def format_datetime(dt: datetime, format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Format datetime to string"""
    return dt.strftime(format_str) if dt else ""


def parse_datetime(
    date_str: str, format_str: str = "%Y-%m-%d %H:%M:%S"
) -> Optional[datetime]:
    """Parse string to datetime"""
    try:
        return datetime.strptime(date_str, format_str)
    except (ValueError, TypeError):
        return None


def is_business_hours(current_time: datetime, open_time: str, close_time: str) -> bool:
    """Check if current time is within business hours"""
    try:
        current_time_only = current_time.time()
        open_dt = datetime.strptime(open_time, "%H:%M").time()
        close_dt = datetime.strptime(close_time, "%H:%M").time()

        # Handle overnight hours
        if close_dt < open_dt:
            return current_time_only >= open_dt or current_time_only <= close_dt
        else:
            return open_dt <= current_time_only <= close_dt
    except ValueError:
        return False


def get_shift_hours(shift_type: str) -> Tuple[str, str]:
    """Get start and end times for shift types"""
    shift_hours = {
        EmployeeConstants.SHIFT_TYPE_MORNING: ("06:00", "14:00"),
        EmployeeConstants.SHIFT_TYPE_AFTERNOON: ("14:00", "22:00"),
        EmployeeConstants.SHIFT_TYPE_EVENING: ("22:00", "06:00"),
    }
    return shift_hours.get(shift_type, ("09:00", "17:00"))


def calculate_age(birth_date: datetime) -> int:
    """Calculate age from birth date"""
    today = datetime.now().date()
    birth = birth_date.date() if isinstance(birth_date, datetime) else birth_date
    return (
        today.year - birth.year - ((today.month, today.day) < (birth.month, birth.day))
    )


def get_week_boundaries(date: datetime = None) -> Tuple[datetime, datetime]:
    """Get start and end of week for given date"""
    if date is None:
        date = datetime.now()

    # Get Monday of the week
    start_of_week = date - timedelta(days=date.weekday())
    start_of_week = start_of_week.replace(hour=0, minute=0, second=0, microsecond=0)

    # Get Sunday of the week
    end_of_week = start_of_week + timedelta(days=6, hours=23, minutes=59, seconds=59)

    return start_of_week, end_of_week


# ================== FINANCIAL UTILITIES ==================


def format_currency(amount: Union[float, Decimal], currency: str = "INR") -> str:
    """Format amount as currency (default INR for India)"""
    if amount is None:
        return f"0.00 {currency}"

    # Convert to Decimal for precision
    decimal_amount = Decimal(str(amount)).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_UP
    )

    # Indian number formatting (lakhs, crores)
    if currency == "INR":
        return format_inr_currency(decimal_amount)
    else:
        return f"{decimal_amount:,.2f} {currency}"


def format_inr_currency(amount: Decimal) -> str:
    """Format amount in Indian Rupee format with lakhs/crores"""
    amount_str = f"{amount:,.2f}"

    # Convert to Indian numbering system
    if amount >= 10000000:  # 1 crore
        crores = amount / 10000000
        return f"₹{crores:.2f} Cr"
    elif amount >= 100000:  # 1 lakh
        lakhs = amount / 100000
        return f"₹{lakhs:.2f} L"
    else:
        return f"₹{amount_str}"


def calculate_tax(
    subtotal: Union[float, Decimal], tax_rate: Union[float, Decimal]
) -> Decimal:
    """Calculate tax amount"""
    subtotal_decimal = Decimal(str(subtotal))
    tax_rate_decimal = Decimal(str(tax_rate))

    tax_amount = subtotal_decimal * tax_rate_decimal
    return tax_amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def calculate_discount(
    original_price: Union[float, Decimal], discount_percent: Union[float, Decimal]
) -> Decimal:
    """Calculate discount amount"""
    original_decimal = Decimal(str(original_price))
    discount_decimal = Decimal(str(discount_percent)) / 100

    discount_amount = original_decimal * discount_decimal
    return discount_amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def calculate_loyalty_points(amount: Union[float, Decimal], tier: str) -> int:
    """Calculate loyalty points earned"""
    earning_rates = CustomerConstants.LOYALTY_POINTS_EARNING_RATE
    rate = earning_rates.get(tier, 1)

    amount_decimal = Decimal(str(amount))
    points = amount_decimal * Decimal(str(rate))
    return int(points)


# ================== INVENTORY UTILITIES ==================


def calculate_reorder_point(
    daily_usage: int, lead_time_days: int, safety_stock: int = 0
) -> int:
    """Calculate inventory reorder point"""
    return (daily_usage * lead_time_days) + safety_stock


def categorize_stock_level(
    current_stock: int, low_threshold: int, critical_threshold: int
) -> str:
    """Categorize stock level status"""
    if current_stock <= critical_threshold:
        return "critical"
    elif current_stock <= low_threshold:
        return "low"
    elif current_stock >= BusinessConstants.OVERSTOCK_THRESHOLD:
        return "overstock"
    else:
        return "normal"


def calculate_inventory_turnover(
    cost_of_goods_sold: Decimal, average_inventory: Decimal
) -> Decimal:
    """Calculate inventory turnover ratio"""
    if average_inventory == 0:
        return Decimal("0")

    turnover = cost_of_goods_sold / average_inventory
    return turnover.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


# ================== PAGINATION UTILITIES ==================


def paginate_query(page: int, page_size: int, total_items: int) -> Dict[str, Any]:
    """Calculate pagination parameters"""
    # Validate inputs
    page = max(1, page)
    page_size = min(max(1, page_size), BusinessConstants.MAX_PAGE_SIZE)

    # Calculate pagination values
    total_pages = (total_items + page_size - 1) // page_size
    offset = (page - 1) * page_size

    # Determine if there are previous/next pages
    has_previous = page > 1
    has_next = page < total_pages

    return {
        "page": page,
        "page_size": page_size,
        "total_items": total_items,
        "total_pages": total_pages,
        "offset": offset,
        "has_previous": has_previous,
        "has_next": has_next,
        "previous_page": page - 1 if has_previous else None,
        "next_page": page + 1 if has_next else None,
    }


# ================== SECURITY UTILITIES ==================


def generate_secure_token(length: int = 32) -> str:
    """Generate cryptographically secure random token"""
    return secrets.token_urlsafe(length)


def hash_data(data: str, salt: str = None) -> str:
    """Hash data with optional salt"""
    if salt is None:
        salt = secrets.token_hex(16)

    hash_input = f"{data}{salt}".encode("utf-8")
    hash_object = hashlib.sha256(hash_input)
    return hash_object.hexdigest()


def mask_sensitive_data(data: str, mask_char: str = "*", visible_chars: int = 4) -> str:
    """Mask sensitive data (e.g., credit card numbers, SSN)"""
    if not data or len(data) <= visible_chars:
        return data

    visible_part = data[-visible_chars:]
    masked_part = mask_char * (len(data) - visible_chars)
    return f"{masked_part}{visible_part}"


def generate_correlation_id() -> str:
    """Generate correlation ID for request tracing"""
    return str(uuid.uuid4())


# ================== DATA TRANSFORMATION UTILITIES ==================


def flatten_dict(
    d: Dict[str, Any], parent_key: str = "", sep: str = "."
) -> Dict[str, Any]:
    """Flatten nested dictionary"""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def unflatten_dict(d: Dict[str, Any], sep: str = ".") -> Dict[str, Any]:
    """Unflatten dictionary with dot notation keys"""
    result = {}
    for key, value in d.items():
        keys = key.split(sep)
        current = result
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        current[keys[-1]] = value
    return result


def deep_merge_dicts(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """Deep merge two dictionaries"""
    result = dict1.copy()
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge_dicts(result[key], value)
        else:
            result[key] = value
    return result


def safe_json_loads(json_str: str, default: Any = None) -> Any:
    """Safely parse JSON string"""
    try:
        return json.loads(json_str)
    except (json.JSONDecodeError, TypeError):
        return default


def safe_json_dumps(obj: Any, default: str = "{}") -> str:
    """Safely serialize object to JSON"""
    try:
        return json.dumps(obj, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        return default


# ================== FILE UTILITIES ==================


def get_file_extension(filename: str) -> str:
    """Get file extension from filename"""
    return filename.split(".")[-1].lower() if "." in filename else ""


def is_allowed_file_type(filename: str, allowed_extensions: List[str]) -> bool:
    """Check if file type is allowed"""
    extension = f".{get_file_extension(filename)}"
    return extension in allowed_extensions


def format_file_size(size_bytes: int) -> str:
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0 B"

    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    size = float(size_bytes)

    while size >= 1024.0 and i < len(size_names) - 1:
        size /= 1024.0
        i += 1

    return f"{size:.1f} {size_names[i]}"


# ================== SEARCH & FILTER UTILITIES ==================


def build_search_query(search_term: str, fields: List[str]) -> Dict[str, Any]:
    """Build MongoDB search query for multiple fields"""
    if not search_term:
        return {}

    # Escape special regex characters
    escaped_term = re.escape(search_term)

    # Create case-insensitive regex pattern
    regex_pattern = {"$regex": escaped_term, "$options": "i"}

    # Build OR query for all specified fields
    or_conditions = [{field: regex_pattern} for field in fields]

    return {"$or": or_conditions}


def apply_filters(
    base_query: Dict[str, Any], filters: Dict[str, Any]
) -> Dict[str, Any]:
    """Apply filters to MongoDB query"""
    query = base_query.copy()

    for field, value in filters.items():
        if value is not None and value != "":
            # Handle range filters (e.g., price_min, price_max)
            if field.endswith("_min"):
                base_field = field[:-4]
                query[base_field] = query.get(base_field, {})
                query[base_field]["$gte"] = value
            elif field.endswith("_max"):
                base_field = field[:-4]
                query[base_field] = query.get(base_field, {})
                query[base_field]["$lte"] = value
            # Handle array filters (e.g., categories)
            elif isinstance(value, list):
                query[field] = {"$in": value}
            # Handle exact matches
            else:
                query[field] = value

    return query


# ================== BUSINESS LOGIC HELPERS ==================


def calculate_shift_duration(start_time: str, end_time: str) -> float:
    """Calculate shift duration in hours"""
    try:
        start = datetime.strptime(start_time, "%H:%M")
        end = datetime.strptime(end_time, "%H:%M")

        # Handle overnight shifts
        if end < start:
            end += timedelta(days=1)

        duration = end - start
        return duration.total_seconds() / 3600  # Convert to hours
    except ValueError:
        return 0.0


def is_peak_hours(
    current_time: datetime, peak_start: str = "11:00", peak_end: str = "14:00"
) -> bool:
    """Check if current time is during peak business hours"""
    return is_business_hours(current_time, peak_start, peak_end)


def calculate_commission(
    sales_amount: Decimal, commission_rate: Decimal, tier: str = "basic"
) -> Decimal:
    """Calculate sales commission based on amount and tier"""
    base_commission = sales_amount * commission_rate

    # Tier-based multipliers
    tier_multipliers = {
        "basic": Decimal("1.0"),
        "silver": Decimal("1.1"),
        "gold": Decimal("1.2"),
        "platinum": Decimal("1.3"),
    }

    multiplier = tier_multipliers.get(tier, Decimal("1.0"))
    final_commission = base_commission * multiplier

    return final_commission.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


# Export all helper functions
__all__ = [
    # String utilities
    "generate_id",
    "generate_tenant_subdomain",
    "generate_sku",
    "generate_employee_id",
    "sanitize_string",
    "slugify",
    # Validation utilities
    "validate_email",
    "validate_phone",
    "validate_sku",
    "validate_barcode",
    "validate_store_hours",
    # Date & time utilities
    "get_current_utc",
    "format_datetime",
    "parse_datetime",
    "is_business_hours",
    "get_shift_hours",
    "calculate_age",
    "get_week_boundaries",
    # Financial utilities
    "format_currency",
    "calculate_tax",
    "calculate_discount",
    "calculate_loyalty_points",
    # Inventory utilities
    "calculate_reorder_point",
    "categorize_stock_level",
    "calculate_inventory_turnover",
    # Pagination utilities
    "paginate_query",
    # Security utilities
    "generate_secure_token",
    "hash_data",
    "mask_sensitive_data",
    "generate_correlation_id",
    # Data transformation utilities
    "flatten_dict",
    "unflatten_dict",
    "deep_merge_dicts",
    "safe_json_loads",
    "safe_json_dumps",
    # File utilities
    "get_file_extension",
    "is_allowed_file_type",
    "format_file_size",
    # Search & filter utilities
    "build_search_query",
    "apply_filters",
    # Business logic helpers
    "calculate_shift_duration",
    "is_peak_hours",
    "calculate_commission",
]


def validate_sku(sku: str) -> bool:
    """Validate SKU format"""
    if not sku:
        return False
    return (
        re.match(RegexPatterns.OBJECTID, sku) is not None
        or re.match(ProductConstants.SKU_PATTERN, sku) is not None
    )


def validate_barcode(barcode: str, barcode_type: str = "UPC") -> bool:
    """Validate barcode format based on type"""
    if not barcode:
        return False

    patterns = ProductConstants.BARCODE_PATTERNS
    if barcode_type not in patterns:
        return False

    return re.match(patterns[barcode_type], barcode) is not None


def validate_store_hours(open_time: str, close_time: str) -> bool:
    """Validate store operating hours"""
    try:
        open_dt = datetime.strptime(open_time, "%H:%M")
        close_dt = datetime.strptime(close_time, "%H:%M")

        # Handle overnight hours (e.g., 22:00 to 06:00)
        if close_dt < open_dt:
            close_dt += timedelta(days=1)

        # Store should be open for at least 1 hour and max 24 hours
        duration = close_dt - open_dt
        return timedelta(hours=1) <= duration <= timedelta(hours=24)
    except ValueError:
        return False


# ================== DATE & TIME UTILITIES ==================


def get_current_utc() -> datetime:
    """Get current UTC datetime"""
    return datetime.now(timezone.utc)


def format_datetime(dt: datetime, format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Format datetime to string"""
    return dt.strftime(format_str) if dt else ""


def parse_datetime(
    date_str: str, format_str: str = "%Y-%m-%d %H:%M:%S"
) -> Optional[datetime]:
    """Parse string to datetime"""
    try:
        return datetime.strptime(date_str, format_str)
    except (ValueError, TypeError):
        return None


def is_business_hours(current_time: datetime, open_time: str, close_time: str) -> bool:
    """Check if current time is within business hours"""
    try:
        current_time_only = current_time.time()
        open_dt = datetime.strptime(open_time, "%H:%M").time()
        close_dt = datetime.strptime(close_time, "%H:%M").time()

        # Handle overnight hours
        if close_dt < open_dt:
            return current_time_only >= open_dt or current_time_only <= close_dt
        else:
            return open_dt <= current_time_only <= close_dt
    except ValueError:
        return False


def get_shift_hours(shift_type: str) -> Tuple[str, str]:
    """Get start and end times for shift types"""
    shift_hours = {
        EmployeeConstants.SHIFT_TYPE_MORNING: ("06:00", "14:00"),
        EmployeeConstants.SHIFT_TYPE_AFTERNOON: ("14:00", "22:00"),
        EmployeeConstants.SHIFT_TYPE_EVENING: ("22:00", "06:00"),
    }
    return shift_hours.get(shift_type, ("09:00", "17:00"))


def calculate_age(birth_date: datetime) -> int:
    """Calculate age from birth date"""
    today = datetime.now().date()
    birth = birth_date.date() if isinstance(birth_date, datetime) else birth_date
    return (
        today.year - birth.year - ((today.month, today.day) < (birth.month, birth.day))
    )


def get_week_boundaries(date: datetime = None) -> Tuple[datetime, datetime]:
    """Get start and end of week for given date"""
    if date is None:
        date = datetime.now()

    # Get Monday of the week
    start_of_week = date - timedelta(days=date.weekday())
    start_of_week = start_of_week.replace(hour=0, minute=0, second=0, microsecond=0)

    # Get Sunday of the week
    end_of_week = start_of_week + timedelta(days=6, hours=23, minutes=59, seconds=59)

    return start_of_week, end_of_week


# ================== FINANCIAL UTILITIES ==================


def format_currency(amount: Union[float, Decimal], currency: str = "INR") -> str:
    """Format amount as currency (default INR for India)"""
    if amount is None:
        return f"0.00 {currency}"

    # Convert to Decimal for precision
    decimal_amount = Decimal(str(amount)).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_UP
    )

    # Indian number formatting (lakhs, crores)
    if currency == "INR":
        return format_inr_currency(decimal_amount)
    else:
        return f"{decimal_amount:,.2f} {currency}"


def format_inr_currency(amount: Decimal) -> str:
    """Format amount in Indian Rupee format with lakhs/crores"""
    amount_str = f"{amount:,.2f}"

    # Convert to Indian numbering system
    if amount >= 10000000:  # 1 crore
        crores = amount / 10000000
        return f"₹{crores:.2f} Cr"
    elif amount >= 100000:  # 1 lakh
        lakhs = amount / 100000
        return f"₹{lakhs:.2f} L"
    else:
        return f"₹{amount_str}"


def calculate_tax(
    subtotal: Union[float, Decimal], tax_rate: Union[float, Decimal]
) -> Decimal:
    """Calculate tax amount"""
    subtotal_decimal = Decimal(str(subtotal))
    tax_rate_decimal = Decimal(str(tax_rate))

    tax_amount = subtotal_decimal * tax_rate_decimal
    return tax_amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def calculate_discount(
    original_price: Union[float, Decimal], discount_percent: Union[float, Decimal]
) -> Decimal:
    """Calculate discount amount"""
    original_decimal = Decimal(str(original_price))
    discount_decimal = Decimal(str(discount_percent)) / 100

    discount_amount = original_decimal * discount_decimal
    return discount_amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def calculate_loyalty_points(amount: Union[float, Decimal], tier: str) -> int:
    """Calculate loyalty points earned"""
    earning_rates = CustomerConstants.LOYALTY_POINTS_EARNING_RATE
    rate = earning_rates.get(tier, 1)

    amount_decimal = Decimal(str(amount))
    points = amount_decimal * Decimal(str(rate))
    return int(points)


# ================== INVENTORY UTILITIES ==================


def calculate_reorder_point(
    daily_usage: int, lead_time_days: int, safety_stock: int = 0
) -> int:
    """Calculate inventory reorder point"""
    return (daily_usage * lead_time_days) + safety_stock


def categorize_stock_level(
    current_stock: int, low_threshold: int, critical_threshold: int
) -> str:
    """Categorize stock level status"""
    if current_stock <= critical_threshold:
        return "critical"
    elif current_stock <= low_threshold:
        return "low"
    elif current_stock >= BusinessConstants.OVERSTOCK_THRESHOLD:
        return "overstock"
    else:
        return "normal"


def calculate_inventory_turnover(
    cost_of_goods_sold: Decimal, average_inventory: Decimal
) -> Decimal:
    """Calculate inventory turnover ratio"""
    if average_inventory == 0:
        return Decimal("0")

    turnover = cost_of_goods_sold / average_inventory
    return turnover.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


# ================== PAGINATION UTILITIES ==================


def paginate_query(page: int, page_size: int, total_items: int) -> Dict[str, Any]:
    """Calculate pagination parameters"""
    # Validate inputs
    page = max(1, page)
    page_size = min(max(1, page_size), BusinessConstants.MAX_PAGE_SIZE)

    # Calculate pagination values
    total_pages = (total_items + page_size - 1) // page_size
    offset = (page - 1) * page_size

    # Determine if there are previous/next pages
    has_previous = page > 1
    has_next = page < total_pages

    return {
        "page": page,
        "page_size": page_size,
        "total_items": total_items,
        "total_pages": total_pages,
        "offset": offset,
        "has_previous": has_previous,
        "has_next": has_next,
        "previous_page": page - 1 if has_previous else None,
        "next_page": page + 1 if has_next else None,
    }


# ================== SECURITY UTILITIES ==================


def generate_secure_token(length: int = 32) -> str:
    """Generate cryptographically secure random token"""
    return secrets.token_urlsafe(length)


def hash_data(data: str, salt: str = None) -> str:
    """Hash data with optional salt"""
    if salt is None:
        salt = secrets.token_hex(16)

    hash_input = f"{data}{salt}".encode("utf-8")
    hash_object = hashlib.sha256(hash_input)
    return hash_object.hexdigest()


def mask_sensitive_data(data: str, mask_char: str = "*", visible_chars: int = 4) -> str:
    """Mask sensitive data (e.g., credit card numbers, SSN)"""
    if not data or len(data) <= visible_chars:
        return data

    visible_part = data[-visible_chars:]
    masked_part = mask_char * (len(data) - visible_chars)
    return f"{masked_part}{visible_part}"


def generate_correlation_id() -> str:
    """Generate correlation ID for request tracing"""
    return str(uuid.uuid4())


# ================== DATA TRANSFORMATION UTILITIES ==================


def flatten_dict(
    d: Dict[str, Any], parent_key: str = "", sep: str = "."
) -> Dict[str, Any]:
    """Flatten nested dictionary"""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def unflatten_dict(d: Dict[str, Any], sep: str = ".") -> Dict[str, Any]:
    """Unflatten dictionary with dot notation keys"""
    result = {}
    for key, value in d.items():
        keys = key.split(sep)
        current = result
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        current[keys[-1]] = value
    return result


def deep_merge_dicts(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """Deep merge two dictionaries"""
    result = dict1.copy()
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge_dicts(result[key], value)
        else:
            result[key] = value
    return result


def safe_json_loads(json_str: str, default: Any = None) -> Any:
    """Safely parse JSON string"""
    try:
        return json.loads(json_str)
    except (json.JSONDecodeError, TypeError):
        return default


def safe_json_dumps(obj: Any, default: str = "{}") -> str:
    """Safely serialize object to JSON"""
    try:
        return json.dumps(obj, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        return default


# ================== FILE UTILITIES ==================


def get_file_extension(filename: str) -> str:
    """Get file extension from filename"""
    return filename.split(".")[-1].lower() if "." in filename else ""


def is_allowed_file_type(filename: str, allowed_extensions: List[str]) -> bool:
    """Check if file type is allowed"""
    extension = f".{get_file_extension(filename)}"
    return extension in allowed_extensions


def format_file_size(size_bytes: int) -> str:
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0 B"

    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    size = float(size_bytes)

    while size >= 1024.0 and i < len(size_names) - 1:
        size /= 1024.0
        i += 1

    return f"{size:.1f} {size_names[i]}"


# ================== SEARCH & FILTER UTILITIES ==================


def build_search_query(search_term: str, fields: List[str]) -> Dict[str, Any]:
    """Build MongoDB search query for multiple fields"""
    if not search_term:
        return {}

    # Escape special regex characters
    escaped_term = re.escape(search_term)

    # Create case-insensitive regex pattern
    regex_pattern = {"$regex": escaped_term, "$options": "i"}

    # Build OR query for all specified fields
    or_conditions = [{field: regex_pattern} for field in fields]

    return {"$or": or_conditions}


def apply_filters(
    base_query: Dict[str, Any], filters: Dict[str, Any]
) -> Dict[str, Any]:
    """Apply filters to MongoDB query"""
    query = base_query.copy()

    for field, value in filters.items():
        if value is not None and value != "":
            # Handle range filters (e.g., price_min, price_max)
            if field.endswith("_min"):
                base_field = field[:-4]
                query[base_field] = query.get(base_field, {})
                query[base_field]["$gte"] = value
            elif field.endswith("_max"):
                base_field = field[:-4]
                query[base_field] = query.get(base_field, {})
                query[base_field]["$lte"] = value
            # Handle array filters (e.g., categories)
            elif isinstance(value, list):
                query[field] = {"$in": value}
            # Handle exact matches
            else:
                query[field] = value

    return query


# ================== BUSINESS LOGIC HELPERS ==================


def calculate_shift_duration(start_time: str, end_time: str) -> float:
    """Calculate shift duration in hours"""
    try:
        start = datetime.strptime(start_time, "%H:%M")
        end = datetime.strptime(end_time, "%H:%M")

        # Handle overnight shifts
        if end < start:
            end += timedelta(days=1)

        duration = end - start
        return duration.total_seconds() / 3600  # Convert to hours
    except ValueError:
        return 0.0


def is_peak_hours(
    current_time: datetime, peak_start: str = "11:00", peak_end: str = "14:00"
) -> bool:
    """Check if current time is during peak business hours"""
    return is_business_hours(current_time, peak_start, peak_end)


def calculate_commission(
    sales_amount: Decimal, commission_rate: Decimal, tier: str = "basic"
) -> Decimal:
    """Calculate sales commission based on amount and tier"""
    base_commission = sales_amount * commission_rate

    # Tier-based multipliers
    tier_multipliers = {
        "basic": Decimal("1.0"),
        "silver": Decimal("1.1"),
        "gold": Decimal("1.2"),
        "platinum": Decimal("1.3"),
    }

    multiplier = tier_multipliers.get(tier, Decimal("1.0"))
    final_commission = base_commission * multiplier

    return final_commission.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


# Export all helper functions
__all__ = [
    # String utilities
    "generate_id",
    "generate_tenant_subdomain",
    "generate_sku",
    "generate_employee_id",
    "sanitize_string",
    "slugify",
    # Validation utilities
    "validate_email",
    "validate_phone",
    "validate_sku",
    "validate_barcode",
    "validate_store_hours",
    # Date & time utilities
    "get_current_utc",
    "format_datetime",
    "parse_datetime",
    "is_business_hours",
    "get_shift_hours",
    "calculate_age",
    "get_week_boundaries",
    # Financial utilities
    "format_currency",
    "calculate_tax",
    "calculate_discount",
    "calculate_loyalty_points",
    # Inventory utilities
    "calculate_reorder_point",
    "categorize_stock_level",
    "calculate_inventory_turnover",
    # Pagination utilities
    "paginate_query",
    # Security utilities
    "generate_secure_token",
    "hash_data",
    "mask_sensitive_data",
    "generate_correlation_id",
    # Data transformation utilities
    "flatten_dict",
    "unflatten_dict",
    "deep_merge_dicts",
    "safe_json_loads",
    "safe_json_dumps",
    # File utilities
    "get_file_extension",
    "is_allowed_file_type",
    "format_file_size",
    # Search & filter utilities
    "build_search_query",
    "apply_filters",
    # Business logic helpers
    "calculate_shift_duration",
    "is_peak_hours",
    "calculate_commission",
]
