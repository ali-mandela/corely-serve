from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field as field


class UnitType(str, Enum):
    PIECE = "piece"
    KG = "kg"
    LITER = "liter"
    PACK = "pack"
    BOX = "box"
    SET = "set"
    OTHER = "other"


class ProductSchema(BaseModel):
    """Schema for product data."""

    # UID can be generated externally or with a UUID if needed
    name: str = field(..., description="Name of the product")
    description: Optional[str] = field(None, description="Product description")
    buying_price: float = field(
        ..., ge=0, description="Buying price must be non-negative"
    )
    selling_price: float = field(
        ..., ge=0, description="Selling price must be non-negative"
    )
    unit: UnitType = field(..., description="Unit type of the product")
    unit_quantity: int = field(
        ..., gt=0, description="Quantity per unit, must be positive"
    )
    brand: Optional[str] = field(None, description="Brand of the product")
    category: Optional[str] = field(None, description="Category of the product")
    available_in_stores: list[str] = field(
        default_factory=list, description="List of store IDs"
    )
    is_featured: bool = field(False, description="Is this a featured product?")
    other_meta: dict = field(default_factory=dict, description="Additional metadata")

    # Pydantic v2 recommended model config
    model_config = ConfigDict(
        populate_by_name=True,
        validate_assignment=True,
        extra="forbid",  # disallow extra fields
        str_strip_whitespace=True,
    )
