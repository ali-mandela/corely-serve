from datetime import datetime
from typing import Optional, List, Dict, Any
from decimal import Decimal
from bson import ObjectId
from pydantic import BaseModel, Field
from app._models.user import PyObjectId


class TaxRule(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    organization_id: PyObjectId
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    
    # Tax configuration
    tax_type: str = "percentage"  # percentage, fixed, compound
    rate: Decimal = Field(..., ge=0, le=1)  # 0.08 for 8%
    fixed_amount: Optional[Decimal] = Field(None, ge=0)  # For fixed tax amounts
    
    # Applicability
    applies_to: str = "all"  # all, category, product, customer_type
    category_ids: List[PyObjectId] = Field(default_factory=list)
    product_ids: List[PyObjectId] = Field(default_factory=list)
    customer_types: List[str] = Field(default_factory=list)  # retail, wholesale, etc.
    
    # Geographic scope
    country: Optional[str] = Field(None, max_length=2)  # ISO country code
    state: Optional[str] = Field(None, max_length=50)
    city: Optional[str] = Field(None, max_length=100)
    zip_codes: List[str] = Field(default_factory=list)
    
    # Store scope
    store_ids: List[PyObjectId] = Field(default_factory=list)  # Empty means all stores
    
    # Validity
    effective_from: Optional[datetime] = None
    effective_until: Optional[datetime] = None
    
    # Status
    is_active: bool = True
    is_default: bool = False
    priority: int = 0  # Higher priority rules override lower ones
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str, Decimal: float}
        json_schema_extra = {
            "example": {
                "name": "General Sales Tax",
                "description": "Standard sales tax for all products",
                "tax_type": "percentage",
                "rate": 0.08,
                "applies_to": "all",
                "country": "US",
                "state": "CA",
                "is_active": True,
                "is_default": True,
                "priority": 1
            }
        }


class TaxCalculation(BaseModel):
    subtotal: Decimal
    tax_amount: Decimal
    total_amount: Decimal
    applied_taxes: List[Dict[str, Any]]
    tax_breakdown: Dict[str, Decimal]