"""
Enterprise Multi-Tenant Stores Management System Data Formatters
This module contains formatting functions for the India-based stores management platform.
"""

import re
from datetime import datetime, date, time
from typing import Any, Dict, List, Optional, Union
from decimal import Decimal, ROUND_HALF_UP
import json
from enum import Enum

from app._core.utils.constants import CustomerConstants, EmployeeConstants


class DateFormat(Enum):
    """Common date format patterns"""

    ISO = "%Y-%m-%d"
    INDIAN = "%d/%m/%Y"
    DISPLAY = "%d %b %Y"
    FULL = "%A, %d %B %Y"
    DATETIME = "%d/%m/%Y %H:%M"
    TIME_12H = "%I:%M %p"
    TIME_24H = "%H:%M"


# ================== CURRENCY & NUMBER FORMATTERS ==================


class CurrencyFormatter:
    """Formatters for Indian currency and numbers"""

    @staticmethod
    def format_inr(
        amount: Union[int, float, Decimal],
        show_symbol: bool = True,
        include_paisa: bool = True,
        use_indian_system: bool = True,
    ) -> str:
        """Format amount in Indian Rupees"""
        if amount is None:
            return "₹0" if show_symbol else "0"

        # Convert to Decimal for precision
        decimal_amount = Decimal(str(amount))

        # Round to 2 decimal places
        rounded_amount = decimal_amount.quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        )

        if use_indian_system:
            return CurrencyFormatter._format_indian_numbering(
                rounded_amount, show_symbol, include_paisa
            )
        else:
            formatted = (
                f"{rounded_amount:,.2f}"
                if include_paisa
                else f"{int(rounded_amount):,}"
            )
            return f"₹{formatted}" if show_symbol else formatted

    @staticmethod
    def _format_indian_numbering(
        amount: Decimal, show_symbol: bool, include_paisa: bool
    ) -> str:
        """Format number using Indian numbering system (lakhs, crores)"""
        abs_amount = abs(amount)
        sign = "-" if amount < 0 else ""

        # Format based on amount size
        if abs_amount >= Decimal("10000000"):  # 1 crore and above
            crores = abs_amount / Decimal("10000000")
            if include_paisa:
                formatted = f"{crores:.2f} Cr"
            else:
                formatted = f"{int(crores)} Cr"
        elif abs_amount >= Decimal("100000"):  # 1 lakh and above
            lakhs = abs_amount / Decimal("100000")
            if include_paisa:
                formatted = f"{lakhs:.2f} L"
            else:
                formatted = f"{int(lakhs)} L"
        elif abs_amount >= Decimal("1000"):  # 1 thousand and above
            thousands = abs_amount / Decimal("1000")
            if include_paisa:
                formatted = f"{thousands:.2f} K"
            else:
                formatted = f"{int(thousands)} K"
        else:
            if include_paisa:
                formatted = f"{abs_amount:.2f}"
            else:
                formatted = f"{int(abs_amount)}"

        symbol = "₹" if show_symbol else ""
        return f"{sign}{symbol}{formatted}"

    @staticmethod
    def format_gst_amount(
        base_amount: Union[int, float, Decimal], gst_rate: Union[int, float] = 18
    ) -> Dict[str, str]:
        """Format GST breakdown for Indian businesses"""
        base = Decimal(str(base_amount))
        rate = Decimal(str(gst_rate)) / 100

        gst_amount = base * rate
        cgst_sgst = gst_amount / 2
        total = base + gst_amount

        return {
            "base_amount": CurrencyFormatter.format_inr(base),
            "gst_rate": f"{gst_rate}%",
            "cgst": CurrencyFormatter.format_inr(cgst_sgst),
            "sgst": CurrencyFormatter.format_inr(cgst_sgst),
            "igst": CurrencyFormatter.format_inr(gst_amount),
            "total_gst": CurrencyFormatter.format_inr(gst_amount),
            "total_amount": CurrencyFormatter.format_inr(total),
        }

    @staticmethod
    def parse_inr_input(input_str: str) -> Optional[Decimal]:
        """Parse Indian currency input string to Decimal"""
        if not input_str:
            return None

        # Remove currency symbols and spaces
        cleaned = re.sub(r"[₹,\s]", "", str(input_str).strip())

        # Handle K, L, Cr suffixes
        multiplier = Decimal("1")
        if cleaned.upper().endswith("CR"):
            multiplier = Decimal("10000000")
            cleaned = cleaned[:-2]
        elif cleaned.upper().endswith("L"):
            multiplier = Decimal("100000")
            cleaned = cleaned[:-1]
        elif cleaned.upper().endswith("K"):
            multiplier = Decimal("1000")
            cleaned = cleaned[:-1]

        try:
            amount = Decimal(cleaned) * multiplier
            return amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        except (ValueError, ArithmeticError):
            return None


# ================== DATE & TIME FORMATTERS ==================


class DateTimeFormatter:
    """Formatters for dates and times in Indian context"""

    @staticmethod
    def format_date(
        date_obj: Union[str, date, datetime],
        format_type: DateFormat = DateFormat.INDIAN,
    ) -> str:
        """Format date according to specified format"""
        if not date_obj:
            return ""

        # Convert string to datetime if needed
        if isinstance(date_obj, str):
            try:
                # Try common formats
                for fmt in ["%Y-%m-%d", "%d/%m/%Y", "%Y-%m-%d %H:%M:%S"]:
                    try:
                        date_obj = datetime.strptime(date_obj, fmt)
                        break
                    except ValueError:
                        continue
                else:
                    return date_obj  # Return original if parsing fails
            except:
                return date_obj

        # Extract date part if datetime
        if isinstance(date_obj, datetime):
            date_part = date_obj.date()
        else:
            date_part = date_obj

        return date_part.strftime(format_type.value)

    @staticmethod
    def format_datetime(
        dt: Union[str, datetime], format_type: DateFormat = DateFormat.DATETIME
    ) -> str:
        """Format datetime in Indian format"""
        if not dt:
            return ""

        if isinstance(dt, str):
            try:
                dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
            except:
                return dt

        return dt.strftime(format_type.value)

    @staticmethod
    def format_time(
        time_obj: Union[str, time, datetime], format_12h: bool = True
    ) -> str:
        """Format time in 12h or 24h format"""
        if not time_obj:
            return ""

        if isinstance(time_obj, str):
            try:
                time_obj = datetime.strptime(time_obj, "%H:%M").time()
            except ValueError:
                try:
                    time_obj = datetime.strptime(time_obj, "%H:%M:%S").time()
                except ValueError:
                    return time_obj

        if isinstance(time_obj, datetime):
            time_obj = time_obj.time()

        fmt = DateFormat.TIME_12H.value if format_12h else DateFormat.TIME_24H.value
        return time_obj.strftime(fmt)

    @staticmethod
    def format_duration(seconds: int) -> str:
        """Format duration in human readable format"""
        if seconds < 60:
            return f"{seconds} sec"
        elif seconds < 3600:
            minutes = seconds // 60
            return f"{minutes} min"
        elif seconds < 86400:
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            return f"{hours}h {minutes}m" if minutes > 0 else f"{hours}h"
        else:
            days = seconds // 86400
            hours = (seconds % 86400) // 3600
            return f"{days}d {hours}h" if hours > 0 else f"{days}d"

    @staticmethod
    def format_business_hours(open_time: str, close_time: str) -> str:
        """Format business hours display"""
        try:
            open_dt = datetime.strptime(open_time, "%H:%M")
            close_dt = datetime.strptime(close_time, "%H:%M")

            open_formatted = open_dt.strftime("%I:%M %p").lower().replace(" 0", " ")
            close_formatted = close_dt.strftime("%I:%M %p").lower().replace(" 0", " ")

            return f"{open_formatted} - {close_formatted}"
        except ValueError:
            return f"{open_time} - {close_time}"


# ================== CONTACT FORMATTERS ==================


class ContactFormatter:
    """Formatters for contact information"""

    @staticmethod
    def format_indian_mobile(mobile: str, include_country_code: bool = True) -> str:
        """Format Indian mobile number"""
        if not mobile:
            return ""

        # Extract digits only
        digits = re.sub(r"[^\d]", "", mobile)

        # Handle different input formats
        if digits.startswith("91") and len(digits) == 12:
            mobile_part = digits[2:]
        elif len(digits) == 10:
            mobile_part = digits
        else:
            return mobile  # Return original if format unclear

        # Format as XXX-XXX-XXXX
        formatted = f"{mobile_part[:3]}-{mobile_part[3:6]}-{mobile_part[6:]}"

        if include_country_code:
            return f"+91 {formatted}"
        else:
            return formatted

    @staticmethod
    def format_landline(landline: str, std_code: str = None) -> str:
        """Format Indian landline number"""
        if not landline:
            return ""

        digits = re.sub(r"[^\d]", "", landline)

        if std_code:
            return f"({std_code}) {digits}"
        elif len(digits) > 8:
            # Assume first 2-4 digits are STD code
            std_len = len(digits) - 7  # Assume 7-digit local number
            std = digits[:std_len]
            local = digits[std_len:]
            return f"({std}) {local}"
        else:
            return digits

    @staticmethod
    def mask_mobile(mobile: str, visible_digits: int = 4) -> str:
        """Mask mobile number for privacy"""
        if not mobile:
            return ""

        formatted = ContactFormatter.format_indian_mobile(mobile, False)
        if len(formatted) < visible_digits:
            return formatted

        masked_part = "X" * (len(formatted) - visible_digits)
        visible_part = formatted[-visible_digits:]
        return f"{masked_part}{visible_part}"

    @staticmethod
    def format_email_display(email: str, max_length: int = 30) -> str:
        """Format email for display with truncation"""
        if not email:
            return ""

        if len(email) <= max_length:
            return email

        username, domain = email.split("@", 1)
        available_length = max_length - len(domain) - 4  # 4 for '@...'

        if available_length > 3:
            truncated_username = username[:available_length] + "..."
            return f"{truncated_username}@{domain}"
        else:
            return email[:max_length] + "..."


# ================== BUSINESS DATA FORMATTERS ==================


class BusinessFormatter:
    """Formatters for business-specific data"""

    @staticmethod
    def format_sku(sku: str) -> str:
        """Format SKU in standard format"""
        if not sku:
            return ""

        # Remove spaces and convert to uppercase
        cleaned = re.sub(r"[^A-Z0-9-]", "", sku.upper())

        # Ensure proper format: XXX-XXX-XXX
        if len(cleaned) >= 9 and "-" not in cleaned:
            return f"{cleaned[:3]}-{cleaned[3:6]}-{cleaned[6:9]}"

        return cleaned

    @staticmethod
    def format_barcode(barcode: str, barcode_type: str = "UPC") -> str:
        """Format barcode for display"""
        if not barcode:
            return ""

        if barcode_type == "UPC" and len(barcode) == 12:
            return f"{barcode[:1]} {barcode[1:6]} {barcode[6:11]} {barcode[11:]}"
        elif barcode_type == "EAN" and len(barcode) == 13:
            return f"{barcode[:1]} {barcode[1:7]} {barcode[7:12]} {barcode[12:]}"
        else:
            return barcode

    @staticmethod
    def format_employee_id(emp_id: str) -> str:
        """Format employee ID for display"""
        if not emp_id:
            return ""

        # Ensure uppercase and proper spacing
        parts = emp_id.upper().split("-")
        if len(parts) == 3:
            return f"{parts[0]}-{parts[1]}-{parts[2]}"

        return emp_id.upper()

    @staticmethod
    def format_store_code(store_name: str, city: str = None) -> str:
        """Generate formatted store code from store name and city"""
        if not store_name:
            return ""

        # Extract first 3 letters from store name
        store_part = re.sub(r"[^A-Z]", "", store_name.upper())[:3]

        if city:
            city_part = re.sub(r"[^A-Z]", "", city.upper())[:2]
            return f"{store_part}{city_part}"

        return store_part + "01"  # Default suffix

    @staticmethod
    def format_inventory_status(
        quantity: int, low_threshold: int = 10, critical_threshold: int = 5
    ) -> Dict[str, str]:
        """Format inventory status with color coding"""
        if quantity <= critical_threshold:
            status = "Critical"
            color = "red"
            icon = "⚠️"
        elif quantity <= low_threshold:
            status = "Low Stock"
            color = "orange"
            icon = "⚡"
        elif quantity > 1000:
            status = "Overstock"
            color = "blue"
            icon = "📦"
        else:
            status = "Normal"
            color = "green"
            icon = "✅"

        return {
            "quantity": f"{quantity:,}",
            "status": status,
            "color": color,
            "icon": icon,
            "display": f"{icon} {quantity:,} ({status})",
        }


# ================== DOCUMENT FORMATTERS ==================


class DocumentFormatter:
    """Formatters for Indian business documents"""

    @staticmethod
    def format_gstin(gstin: str) -> str:
        """Format GSTIN for display"""
        if not gstin:
            return ""

        gstin = gstin.upper().strip()
        if len(gstin) == 15:
            return f"{gstin[:2]} {gstin[2:7]} {gstin[7:11]} {gstin[11:12]} {gstin[12:13]} {gstin[13:14]} {gstin[14:]}"

        return gstin

    @staticmethod
    def format_pan(pan: str) -> str:
        """Format PAN for display"""
        if not pan:
            return ""

        pan = pan.upper().strip()
        if len(pan) == 10:
            return f"{pan[:5]} {pan[5:9]} {pan[9:]}"

        return pan

    @staticmethod
    def format_aadhaar(aadhaar: str, mask: bool = True) -> str:
        """Format Aadhaar number with optional masking"""
        if not aadhaar:
            return ""

        # Remove existing formatting
        digits = re.sub(r"[^\d]", "", aadhaar)

        if len(digits) == 12:
            if mask:
                # Show only last 4 digits
                return f"XXXX XXXX {digits[8:12]}"
            else:
                return f"{digits[:4]} {digits[4:8]} {digits[8:12]}"

        return aadhaar

    @staticmethod
    def format_ifsc(ifsc: str) -> str:
        """Format IFSC code for display"""
        if not ifsc:
            return ""

        ifsc = ifsc.upper().strip()
        if len(ifsc) == 11:
            return f"{ifsc[:4]} 0 {ifsc[5:]}"

        return ifsc

    @staticmethod
    def format_pincode(pincode: str) -> str:
        """Format PIN code for display"""
        if not pincode:
            return ""

        digits = re.sub(r"[^\d]", "", pincode)
        if len(digits) == 6:
            return f"{digits[:3]} {digits[3:]}"

        return pincode


# ================== REPORT FORMATTERS ==================


class ReportFormatter:
    """Formatters for reports and analytics"""

    @staticmethod
    def format_percentage(
        value: Union[int, float, Decimal], decimal_places: int = 1
    ) -> str:
        """Format percentage with proper rounding"""
        if value is None:
            return "0%"

        decimal_value = Decimal(str(value))
        rounded = decimal_value.quantize(
            Decimal(f'0.{"0" * decimal_places}'), rounding=ROUND_HALF_UP
        )
        return f"{rounded}%"

    @staticmethod
    def format_growth_rate(
        current: Union[int, float], previous: Union[int, float]
    ) -> Dict[str, str]:
        """Format growth rate with trend indication"""
        if not previous or previous == 0:
            return {"rate": "N/A", "trend": "neutral", "display": "N/A"}

        growth = ((current - previous) / previous) * 100
        growth_decimal = Decimal(str(growth))
        rounded_growth = growth_decimal.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)

        if growth > 0:
            trend = "up"
            icon = "📈"
            color = "green"
        elif growth < 0:
            trend = "down"
            icon = "📉"
            color = "red"
        else:
            trend = "neutral"
            icon = "➡️"
            color = "gray"

        return {
            "rate": f"{abs(rounded_growth)}%",
            "trend": trend,
            "color": color,
            "icon": icon,
            "display": f"{icon} {abs(rounded_growth)}%",
        }

    @staticmethod
    def format_sales_summary(
        sales_data: Dict[str, Union[int, float]],
    ) -> Dict[str, str]:
        """Format sales summary for dashboard display"""
        total_sales = Decimal(str(sales_data.get("total_sales", 0)))
        total_orders = int(sales_data.get("total_orders", 0))
        avg_order_value = (
            total_sales / total_orders if total_orders > 0 else Decimal("0")
        )

        return {
            "total_sales": CurrencyFormatter.format_inr(total_sales),
            "total_orders": f"{total_orders:,}",
            "avg_order_value": CurrencyFormatter.format_inr(avg_order_value),
            "orders_per_day": f"{sales_data.get('orders_per_day', 0):.1f}",
            "revenue_per_day": CurrencyFormatter.format_inr(
                sales_data.get("revenue_per_day", 0)
            ),
        }


# ================== UTILITY FORMATTERS ==================


class UtilityFormatter:
    """General utility formatters"""

    @staticmethod
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

    @staticmethod
    def format_address(address_data: Dict[str, str]) -> str:
        """Format Indian address for display"""
        components = []

        # Building/House number and street
        if address_data.get("building"):
            components.append(address_data["building"])
        if address_data.get("street"):
            components.append(address_data["street"])

        # Area/Locality
        if address_data.get("area"):
            components.append(address_data["area"])

        # City
        if address_data.get("city"):
            components.append(address_data["city"])

        # State and PIN code
        state_pin = []
        if address_data.get("state"):
            state_pin.append(address_data["state"])
        if address_data.get("pincode"):
            state_pin.append(DocumentFormatter.format_pincode(address_data["pincode"]))

        if state_pin:
            components.append(" - ".join(state_pin))

        return ", ".join(components)

    @staticmethod
    def format_list_display(items: List[str], max_items: int = 3) -> str:
        """Format list for display with 'and X more' suffix"""
        if not items:
            return ""

        if len(items) <= max_items:
            if len(items) == 1:
                return items[0]
            elif len(items) == 2:
                return f"{items[0]} and {items[1]}"
            else:
                return ", ".join(items[:-1]) + f" and {items[-1]}"
        else:
            displayed = items[:max_items]
            remaining = len(items) - max_items
            return ", ".join(displayed) + f" and {remaining} more"

    @staticmethod
    def truncate_text(text: str, max_length: int = 50, suffix: str = "...") -> str:
        """Truncate text with suffix"""
        if not text:
            return ""

        if len(text) <= max_length:
            return text

        return text[: max_length - len(suffix)] + suffix


# Export all formatter classes
__all__ = [
    "DateFormat",
    "CurrencyFormatter",
    "DateTimeFormatter",
    "ContactFormatter",
    "BusinessFormatter",
    "DocumentFormatter",
    "ReportFormatter",
    "UtilityFormatter",
]
