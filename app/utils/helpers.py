from typing import Any, Dict, Optional
from datetime import datetime
from bson import ObjectId
import re
from fastapi import HTTPException
from typing import Any, Dict, Optional
from fastapi.responses import JSONResponse


from datetime import datetime
from bson import ObjectId


def serialize_mongo_doc(doc):
    """Recursively convert ObjectIds and datetimes in a Mongo document."""
    if not doc:
        return doc

    if isinstance(doc, list):
        return [serialize_mongo_doc(d) for d in doc]

    if isinstance(doc, dict):
        clean = {}
        for k, v in doc.items():
            if isinstance(v, ObjectId):
                clean[k] = str(v)
            elif isinstance(v, datetime):
                clean[k] = v.isoformat()
            elif isinstance(v, (dict, list)):
                clean[k] = serialize_mongo_doc(v)
            else:
                clean[k] = v
        return clean

    return doc


def serialize_document(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Convert MongoDB document to JSON-serializable dict"""
    if not doc:
        return {}
    serialized = {k: (str(v) if isinstance(v, ObjectId) else v) for k, v in doc.items()}
    if "created_at" in serialized and isinstance(serialized["created_at"], datetime):
        serialized["created_at"] = serialized["created_at"].isoformat()
    if "updated_at" in serialized and isinstance(serialized["updated_at"], datetime):
        serialized["updated_at"] = serialized["updated_at"].isoformat()
    if "last_login" in serialized and isinstance(serialized["last_login"], datetime):
        serialized["last_login"] = serialized["last_login"].isoformat()
    return serialized


def stringify_object_id(obj_id) -> str:
    """Convert ObjectId to string"""
    return str(obj_id) if obj_id else None


def serialize_datetime(dt: datetime) -> str:
    """Convert datetime to ISO string"""
    return dt.isoformat() if dt else None


def parse_object_id(id_str: str) -> ObjectId:
    """Convert string to ObjectId"""
    try:
        return ObjectId(id_str)
    except Exception:
        raise ValueError("Invalid ObjectId format")


def generate_invoice_number(store_id: str) -> str:
    """Generate unique invoice number"""
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    store_suffix = str(store_id)[-4:] if len(str(store_id)) >= 4 else str(store_id)
    return f"INV-{timestamp}-{store_suffix}"


def validate_phone(phone: str) -> bool:
    """Validate phone number format"""
    pattern = r"^\+?1?-?\.?\s?\(?\d{3}\)?-?\.?\s?\d{3}-?\.?\s?\d{4}$"
    return bool(re.match(pattern, phone))


def calculate_pagination(page: int, per_page: int, total: int) -> Dict[str, Any]:
    """Calculate pagination metadata"""
    import math

    has_next = (page * per_page) < total
    has_prev = page > 1
    pages = math.ceil(total / per_page) if total > 0 else 1

    return {
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": pages,
        "has_next": has_next,
        "has_prev": has_prev,
    }


def format_currency(amount: float, currency: str = "USD") -> str:
    """Format amount as currency"""
    if currency == "USD":
        return f"${amount:,.2f}"
    return f"{amount:,.2f} {currency}"


def error_response(
    message: str, code: int = 400, data: Optional[Any] = None
) -> JSONResponse:
    """Standard error response format"""
    if data is not None:
        content = {
            "success": False,
            "error": {"code": code, "message": message},
            "data": data,
        }
    else:
        content = {"success": False, "error": {"code": code, "message": message}}
    return JSONResponse(status_code=code, content=content)


def success_response(
    data: Optional[Any] = None, message: str = "Success", code: int = 200
) -> JSONResponse:
    """Standard success response format"""
    if data is not None:
        content = {"success": True, "data": data}
    else:
        content = {"success": True, "code": code, "message": message}

    return JSONResponse(status_code=code, content=content)


# import traceback
def logger(value, file_name="log", file_type="json"):
    import os

    from bson import json_util

    try:
        os.makedirs("log_files", exist_ok=True)
        if file_type == "json":
            with open(f"log_files/{file_name}.json", "w") as f:
                f.write(json_util.dumps(value, indent=4))
        else:
            with open(f"log_files/{file_name}.txt", "w") as f:
                f.write(str(value))
        print(f"Successfully wrote data to {file_name} file")

    except Exception as e:
        print(f"Failed to write to file: {e}")
