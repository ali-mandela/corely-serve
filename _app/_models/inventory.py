from datetime import datetime
from bson import ObjectId
from pydantic import BaseModel, Field, validator
from app._models.user import PyObjectId


class Inventory(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    product_id: PyObjectId = Field(..., description="Reference to Product")
    store_id: PyObjectId = Field(..., description="Reference to Store")
    quantity: int = Field(..., ge=0, description="Available quantity")
    reserved_quantity: int = Field(0, ge=0, description="Quantity reserved for pending orders")
    last_updated: datetime = Field(default_factory=datetime.utcnow)
    reorder_point: int = Field(0, ge=0, description="Minimum stock level for reordering")
    max_stock: int = Field(0, ge=0, description="Maximum stock level")

    @validator('reserved_quantity')
    def reserved_cannot_exceed_quantity(cls, v, values):
        if 'quantity' in values and v > values['quantity']:
            raise ValueError('Reserved quantity cannot exceed available quantity')
        return v

    @property
    def available_quantity(self) -> int:
        """Calculate available quantity (total - reserved)"""
        return self.quantity - self.reserved_quantity

    @property
    def needs_reorder(self) -> bool:
        """Check if stock level is below reorder point"""
        return self.quantity <= self.reorder_point

    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        json_schema_extra = {
            "example": {
                "product_id": "507f1f77bcf86cd799439011",
                "store_id": "507f1f77bcf86cd799439012", 
                "quantity": 50,
                "reserved_quantity": 5,
                "reorder_point": 10,
                "max_stock": 100
            }
        }