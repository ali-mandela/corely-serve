from datetime import datetime
from typing import Optional, List, Dict, Any
from bson import ObjectId
from pydantic import BaseModel, Field
from app._models.user import PyObjectId


class Category(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    organization_id: PyObjectId
    name: str = Field(..., min_length=1, max_length=100)
    slug: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    parent_id: Optional[PyObjectId] = None  # For hierarchical categories
    
    # Category properties
    image_url: Optional[str] = None
    icon: Optional[str] = None
    color: Optional[str] = None
    
    # Store type relevance
    store_types: List[str] = Field(default_factory=lambda: ["general"])  # retail, restaurant, service, etc.
    
    # SEO
    meta_title: Optional[str] = Field(None, max_length=200)
    meta_description: Optional[str] = Field(None, max_length=300)
    
    # Status
    is_active: bool = True
    sort_order: int = 0
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        json_schema_extra = {
            "example": {
                "name": "Electronics",
                "slug": "electronics",
                "description": "Electronic devices and accessories",
                "store_types": ["retail", "electronics"],
                "is_active": True,
                "sort_order": 1
            }
        }


class CategoryStats(BaseModel):
    category_id: str
    category_name: str
    product_count: int
    total_inventory_value: float
    avg_product_price: float
    top_selling_products: List[Dict[str, Any]]
    revenue_last_30_days: float