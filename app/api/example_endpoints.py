from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.core.access_control.abac import (
    get_abac_context, get_abac_decision, ABACContext
)


# Example data models
class User(BaseModel):
    id: str
    username: str
    email: str
    department: str
    roles: List[str]
    is_active: bool


class Document(BaseModel):
    id: str
    title: str
    content: str
    owner_id: str
    department: str
    sensitivity: str = "public"  # public, internal, confidential
    created_at: str


class CreateDocumentRequest(BaseModel):
    title: str
    content: str
    sensitivity: str = "public"


# Mock database
MOCK_USERS = {
    "user123": User(
        id="user123",
        username="john_doe",
        email="john@example.com",
        department="engineering",
        roles=["user"],
        is_active=True
    ),
    "admin456": User(
        id="admin456",
        username="admin",
        email="admin@example.com",
        department="it",
        roles=["admin"],
        is_active=True
    )
}

MOCK_DOCUMENTS = {
    "doc1": Document(
        id="doc1",
        title="Public Document",
        content="This is public content",
        owner_id="user123",
        department="engineering",
        sensitivity="public",
        created_at="2024-01-01T10:00:00Z"
    ),
    "doc2": Document(
        id="doc2",
        title="Confidential Report",
        content="This is confidential content",
        owner_id="admin456",
        department="it",
        sensitivity="confidential",
        created_at="2024-01-01T15:00:00Z"
    )
}

router = APIRouter(prefix="/api/v1", tags=["ABAC Examples"])


@router.get("/users/me")
async def get_current_user(
    abac_context: ABACContext = Depends(get_abac_context)
) -> User:
    """Get current user information - demonstrates basic ABAC context usage"""
    user_id = abac_context.user_id
    if not user_id or user_id not in MOCK_USERS:
        raise HTTPException(status_code=404, detail="User not found")

    return MOCK_USERS[user_id]


@router.get("/users/{user_id}")
async def get_user_by_id(
    user_id: str,
    abac_context: ABACContext = Depends(get_abac_context),
    abac_decision = Depends(get_abac_decision)
) -> User:
    """Get user by ID - demonstrates resource-specific access control"""

    # The ABAC middleware has already evaluated access, but we can add additional checks
    if user_id not in MOCK_USERS:
        raise HTTPException(status_code=404, detail="User not found")

    # Example: Check if user is accessing their own profile or is admin
    current_user_id = abac_context.user_id
    is_admin = "admin" in abac_context.roles
    is_self = current_user_id == user_id

    if not (is_self or is_admin):
        raise HTTPException(
            status_code=403,
            detail="You can only access your own profile or must be an admin"
        )

    return MOCK_USERS[user_id]


@router.get("/documents")
async def list_documents(
    abac_context: ABACContext = Depends(get_abac_context)
) -> List[Document]:
    """List documents - demonstrates filtering based on ABAC context"""

    # Filter documents based on user's department and role
    user_dept = abac_context.department
    is_admin = "admin" in abac_context.roles
    user_id = abac_context.user_id

    filtered_docs = []
    for doc in MOCK_DOCUMENTS.values():
        # Admins can see all documents
        if is_admin:
            filtered_docs.append(doc)
            continue

        # Users can see public documents
        if doc.sensitivity == "public":
            filtered_docs.append(doc)
            continue

        # Users can see their own documents
        if doc.owner_id == user_id:
            filtered_docs.append(doc)
            continue

        # Users can see internal documents from their department
        if doc.sensitivity == "internal" and doc.department == user_dept:
            filtered_docs.append(doc)
            continue

    return filtered_docs


@router.get("/documents/{doc_id}")
async def get_document(
    doc_id: str,
    abac_context: ABACContext = Depends(get_abac_context)
) -> Document:
    """Get specific document - demonstrates resource ownership checks"""

    if doc_id not in MOCK_DOCUMENTS:
        raise HTTPException(status_code=404, detail="Document not found")

    doc = MOCK_DOCUMENTS[doc_id]
    user_id = abac_context.user_id
    user_dept = abac_context.department
    is_admin = "admin" in abac_context.roles

    # Check access based on document sensitivity and user attributes
    if doc.sensitivity == "public":
        return doc
    elif doc.sensitivity == "internal":
        if doc.department == user_dept or is_admin:
            return doc
    elif doc.sensitivity == "confidential":
        if doc.owner_id == user_id or is_admin:
            return doc

    raise HTTPException(
        status_code=403,
        detail="Insufficient permissions to access this document"
    )


@router.post("/documents")
async def create_document(
    request_data: CreateDocumentRequest,
    abac_context: ABACContext = Depends(get_abac_context)
) -> Document:
    """Create new document - demonstrates creation with ABAC context"""

    user_id = abac_context.user_id
    user_dept = abac_context.department

    if not user_id:
        raise HTTPException(status_code=401, detail="User not authenticated")

    # Check if user can create documents with this sensitivity level
    if request_data.sensitivity == "confidential" and "admin" not in abac_context.roles:
        raise HTTPException(
            status_code=403,
            detail="Only administrators can create confidential documents"
        )

    # Create new document
    doc_id = f"doc{len(MOCK_DOCUMENTS) + 1}"
    new_doc = Document(
        id=doc_id,
        title=request_data.title,
        content=request_data.content,
        owner_id=user_id,
        department=user_dept or "unknown",
        sensitivity=request_data.sensitivity,
        created_at="2024-01-01T12:00:00Z"
    )

    MOCK_DOCUMENTS[doc_id] = new_doc
    return new_doc


@router.delete("/documents/{doc_id}")
async def delete_document(
    doc_id: str,
    abac_context: ABACContext = Depends(get_abac_context)
) -> Dict[str, str]:
    """Delete document - demonstrates ownership and admin checks"""

    if doc_id not in MOCK_DOCUMENTS:
        raise HTTPException(status_code=404, detail="Document not found")

    doc = MOCK_DOCUMENTS[doc_id]
    user_id = abac_context.user_id
    is_admin = "admin" in abac_context.roles

    # Only owner or admin can delete
    if doc.owner_id != user_id and not is_admin:
        raise HTTPException(
            status_code=403,
            detail="You can only delete your own documents or must be an admin"
        )

    # Additional check: confidential documents can only be deleted by admins
    if doc.sensitivity == "confidential" and not is_admin:
        raise HTTPException(
            status_code=403,
            detail="Only administrators can delete confidential documents"
        )

    del MOCK_DOCUMENTS[doc_id]
    return {"message": "Document deleted successfully"}


@router.get("/admin/users")
async def admin_list_users(
    abac_context: ABACContext = Depends(get_abac_context)
) -> List[User]:
    """Admin endpoint - demonstrates role-based access"""

    if "admin" not in abac_context.roles:
        raise HTTPException(
            status_code=403,
            detail="Administrator privileges required"
        )

    return list(MOCK_USERS.values())


@router.get("/debug/abac-context")
async def debug_abac_context(
    abac_context: ABACContext = Depends(get_abac_context),
    abac_decision = Depends(get_abac_decision)
) -> Dict[str, Any]:
    """Debug endpoint to view ABAC context and decision"""

    return {
        "abac_context": abac_context.model_dump(),
        "abac_decision": {
            "decision": abac_decision.decision,
            "applicable_policies": abac_decision.applicable_policies,
            "reasons": abac_decision.reasons,
            "evaluation_time_ms": abac_decision.evaluation_time_ms
        }
    }