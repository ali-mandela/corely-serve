from typing import List, Optional
from pydantic import BaseModel, Field, validator
from app._models.user import PyObjectId


class InventoryCreate(BaseModel):
    product_id: PyObjectId
    store_id: PyObjectId
    quantity: int = Field(..., ge=0)
    reorder_point: int = Field(0, ge=0)
    max_stock: int = Field(0, ge=0)


class InventoryUpdate(BaseModel):
    quantity: Optional[int] = Field(None, ge=0)
    reserved_quantity: Optional[int] = Field(None, ge=0)
    reorder_point: Optional[int] = Field(None, ge=0)
    max_stock: Optional[int] = Field(None, ge=0)


class InventoryAdjustment(BaseModel):
    product_id: PyObjectId
    store_id: PyObjectId
    adjustment_quantity: int  # Can be positive or negative
    reason: str = Field(..., min_length=1, max_length=200)
    notes: Optional[str] = Field(None, max_length=500)


class InventoryTransfer(BaseModel):
    product_id: PyObjectId
    from_store_id: PyObjectId
    to_store_id: PyObjectId
    quantity: int = Field(..., gt=0)
    notes: Optional[str] = Field(None, max_length=500)


class InventoryResponse(BaseModel):
    id: PyObjectId = Field(..., alias="_id")
    product_id: PyObjectId
    store_id: PyObjectId
    quantity: int
    reserved_quantity: int
    available_quantity: int
    reorder_point: int
    max_stock: int
    needs_reorder: bool
    last_updated: str
    product_name: Optional[str] = None  # Populated via join
    product_sku: Optional[str] = None   # Populated via join
    store_name: Optional[str] = None    # Populated via join

    class Config:
        populate_by_name = True


class InventoryList(BaseModel):
    inventory: List[InventoryResponse]
    total: int
    low_stock_count: int
    out_of_stock_count: int


class StockAlert(BaseModel):
    product_id: PyObjectId
    store_id: PyObjectId
    product_name: str
    product_sku: str
    store_name: str
    current_quantity: int
    reorder_point: int
    alert_type: str  # "low_stock" or "out_of_stock"