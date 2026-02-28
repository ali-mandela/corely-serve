from typing import List, Optional, Dict, Any
from decimal import Decimal
from pydantic import BaseModel, Field, validator
from app._models.user import PyObjectId


class ProductCreate(BaseModel):
    sku: str = Field(..., min_length=1, max_length=50)
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    category: str = Field(..., min_length=1, max_length=100)
    subcategory: Optional[str] = Field(None, max_length=100)
    brand: Optional[str] = Field(None, max_length=100)
    
    # Product type and attributes
    product_type: str = "physical"
    unit: str = Field(..., min_length=1, max_length=20)
    
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
    supplier_id: Optional[str] = None
    supplier_sku: Optional[str] = Field(None, max_length=50)
    
    # Product identification
    barcode: Optional[str] = Field(None, max_length=50)
    upc: Optional[str] = Field(None, max_length=20)
    internal_code: Optional[str] = Field(None, max_length=50)
    
    # Product attributes
    weight: Optional[Decimal] = Field(None, ge=0)
    dimensions: Optional[Dict[str, Decimal]] = None
    color: Optional[str] = Field(None, max_length=50)
    size: Optional[str] = Field(None, max_length=50)
    
    # Additional information
    specifications: Dict[str, Any] = Field(default_factory=dict)
    images: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    
    # Status and tracking
    is_featured: bool = False
    track_inventory: bool = True
    allow_backorder: bool = False
    
    # SEO and online presence
    meta_title: Optional[str] = Field(None, max_length=200)
    meta_description: Optional[str] = Field(None, max_length=300)
    slug: Optional[str] = Field(None, max_length=100)

    @validator('selling_price')
    def selling_price_validation(cls, v, values):
        if v <= 0:
            raise ValueError('Selling price must be positive')
        if 'cost_price' in values and v < values['cost_price']:
            raise ValueError('Selling price should not be less than cost price')
        return v


class ProductUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    category: Optional[str] = Field(None, min_length=1, max_length=100)
    subcategory: Optional[str] = Field(None, max_length=100)
    brand: Optional[str] = Field(None, max_length=100)
    unit: Optional[str] = Field(None, min_length=1, max_length=20)
    cost_price: Optional[Decimal] = Field(None, ge=0)
    selling_price: Optional[Decimal] = Field(None, ge=0)
    min_stock_level: Optional[int] = Field(None, ge=0)
    supplier_id: Optional[PyObjectId] = None
    barcode: Optional[str] = Field(None, max_length=50)
    specifications: Optional[Dict[str, Any]] = None
    images: Optional[List[str]] = None
    is_active: Optional[bool] = None


class ProductResponse(BaseModel):
    id: PyObjectId = Field(..., alias="_id")
    sku: str
    name: str
    description: Optional[str] = None
    category: str
    subcategory: Optional[str] = None
    brand: Optional[str] = None
    unit: str
    cost_price: Decimal
    selling_price: Decimal
    min_stock_level: int
    supplier_id: Optional[PyObjectId] = None
    barcode: Optional[str] = None
    specifications: Dict[str, Any]
    images: List[str]
    is_active: bool
    created_at: str

    class Config:
        populate_by_name = True
        json_encoders = {Decimal: float}


class ProductList(BaseModel):
    products: List[ProductResponse]
    total: int
    page: int
    per_page: int
    has_next: bool
    has_prev: bool