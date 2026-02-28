from datetime import datetime
from typing import List, Optional, Dict, Any
from decimal import Decimal
from bson import ObjectId
from pydantic import BaseModel, Field, validator
from app._models.user import PyObjectId


class Product(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    organization_id: PyObjectId
    sku: str = Field(..., min_length=1, max_length=50)
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    category: str = Field(..., min_length=1, max_length=100)
    subcategory: Optional[str] = Field(None, max_length=100)
    brand: Optional[str] = Field(None, max_length=100)
    
    # Product type and attributes
    product_type: str = "physical"  # physical, digital, service
    unit: str = Field(..., min_length=1, max_length=20)  # piece, kg, meter, hour, etc.
    
    # Pricing
    cost_price: Decimal = Field(..., ge=0)
    selling_price: Decimal = Field(..., ge=0)
    discount_price: Optional[Decimal] = Field(None, ge=0)
    
    # Inventory management
    min_stock_level: int = Field(0, ge=0)
    max_stock_level: Optional[int] = Field(None, ge=0)
    reorder_point: Optional[int] = Field(None, ge=0)
    reorder_quantity: Optional[int] = Field(None, gt=0)
    
    # Supplier and vendor info
    supplier_id: Optional[PyObjectId] = None
    supplier_sku: Optional[str] = Field(None, max_length=50)
    
    # Product identification
    barcode: Optional[str] = Field(None, max_length=50)
    upc: Optional[str] = Field(None, max_length=20)
    internal_code: Optional[str] = Field(None, max_length=50)
    
    # Product attributes
    weight: Optional[Decimal] = Field(None, ge=0)
    dimensions: Optional[Dict[str, Decimal]] = None  # length, width, height
    color: Optional[str] = Field(None, max_length=50)
    size: Optional[str] = Field(None, max_length=50)
    
    # Additional information
    specifications: Dict[str, Any] = Field(default_factory=dict)
    images: List[str] = Field(default_factory=list)  # URLs or file paths
    tags: List[str] = Field(default_factory=list)
    
    # Status and tracking
    is_active: bool = True
    is_featured: bool = False
    track_inventory: bool = True
    allow_backorder: bool = False
    
    # SEO and online presence
    meta_title: Optional[str] = Field(None, max_length=200)
    meta_description: Optional[str] = Field(None, max_length=300)
    slug: Optional[str] = Field(None, max_length=100)
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    @validator('selling_price')
    def selling_price_must_be_positive(cls, v, values):
        if v <= 0:
            raise ValueError('Selling price must be positive')
        if 'cost_price' in values and v < values['cost_price']:
            raise ValueError('Selling price should not be less than cost price')
        return v

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str, Decimal: float}
        json_schema_extra = {
            "example": {
                "sku": "PROD-001",
                "name": "Universal Product",
                "description": "A versatile product for any store type",
                "category": "General",
                "subcategory": "Standard",
                "brand": "Generic Brand",
                "product_type": "physical",
                "unit": "piece",
                "cost_price": 10.00,
                "selling_price": 15.99,
                "discount_price": 14.99,
                "min_stock_level": 5,
                "max_stock_level": 100,
                "reorder_point": 10,
                "reorder_quantity": 50,
                "barcode": "123456789012",
                "weight": 0.5,
                "dimensions": {"length": 10, "width": 5, "height": 2},
                "color": "Blue",
                "size": "Medium",
                "specifications": {
                    "material": "plastic",
                    "warranty": "1 year"
                },
                "tags": ["popular", "bestseller"],
                "is_active": True,
                "is_featured": False,
                "track_inventory": True
            }
        }