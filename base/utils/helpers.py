from datetime import datetime
from typing import Any, Optional
from bson import ObjectId
from fastapi.responses import JSONResponse


def serialize_mongo_doc(doc):
    """Recursively convert ObjectIds and datetimes in a MongoDB document."""
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


def parse_object_id(id_str: str) -> ObjectId:
    """Safely convert a string to ObjectId."""
    if not ObjectId.is_valid(id_str):
        raise ValueError(f"Invalid ObjectId: {id_str}")
    return ObjectId(id_str)


def success_response(
    data: Optional[Any] = None,
    message: str = "Success",
    code: int = 200,
) -> JSONResponse:
    """Standard success JSON response."""
    content = {"success": True, "message": message}
    if data is not None:
        content["data"] = data
    return JSONResponse(status_code=code, content=content)


def error_response(
    message: str,
    code: int = 400,
    data: Optional[Any] = None,
) -> JSONResponse:
    """Standard error JSON response."""
    content = {"success": False, "error": {"code": code, "message": message}}
    if data is not None:
        content["data"] = data
    return JSONResponse(status_code=code, content=content)
