"""
Item / Product schemas — designed for construction & hardware businesses.

Covers: building materials, plumbing, electrical, tools, paint, steel,
timber, cement, tiles, safety gear, fasteners, etc.
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional, List
from enum import Enum
import re


# ── Enums ────────────────────────────────────────────────────────


class ItemCategoryEnum(str, Enum):
    """Primary item categories for construction & hardware."""

    CEMENT_CONCRETE = "cement_concrete"
    STEEL_METALS = "steel_metals"
    TIMBER_PLYWOOD = "timber_plywood"
    BRICKS_BLOCKS = "bricks_blocks"
    SAND_AGGREGATES = "sand_aggregates"
    PAINTS_COATINGS = "paints_coatings"
    PLUMBING = "plumbing"
    ELECTRICAL = "electrical"
    TILES_FLOORING = "tiles_flooring"
    ROOFING = "roofing"
    DOORS_WINDOWS = "doors_windows"
    TOOLS_EQUIPMENT = "tools_equipment"
    FASTENERS_HARDWARE = "fasteners_hardware"
    SAFETY_GEAR = "safety_gear"
    ADHESIVES_SEALANTS = "adhesives_sealants"
    GLASS = "glass"
    WATERPROOFING = "waterproofing"
    PIPES_FITTINGS = "pipes_fittings"
    WIRES_CABLES = "wires_cables"
    LIGHTING = "lighting"
    BATHROOM_SANITARY = "bathroom_sanitary"
    KITCHEN_FITTINGS = "kitchen_fittings"
    GARDEN_OUTDOOR = "garden_outdoor"
    POWER_TOOLS = "power_tools"
    PAINT_FINISHING = "paint_finishing"
    OTHER = "other"


class UnitOfMeasurement(str, Enum):
    """Units commonly used in construction & hardware."""

    # Weight
    KG = "kg"
    GRAM = "g"
    QUINTAL = "quintal"
    TON = "ton"

    # Length
    METER = "m"
    CENTIMETER = "cm"
    MILLIMETER = "mm"
    FOOT = "ft"
    INCH = "in"

    # Area
    SQ_METER = "sq_m"
    SQ_FOOT = "sq_ft"

    # Volume
    LITER = "ltr"
    MILLILITER = "ml"
    CUBIC_METER = "cu_m"
    CUBIC_FOOT = "cu_ft"

    # Quantity
    PIECE = "pcs"
    PAIR = "pair"
    SET = "set"
    BOX = "box"
    BUNDLE = "bundle"
    BAG = "bag"
    PACKET = "pkt"
    ROLL = "roll"
    DOZEN = "dozen"
    SHEET = "sheet"
    COIL = "coil"
    DRUM = "drum"
    CART = "cart"
    TRUCK = "truck"
    CFT = "cft"


class ItemStatusEnum(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DISCONTINUED = "discontinued"
    OUT_OF_STOCK = "out_of_stock"


class TaxSlabEnum(str, Enum):
    """GST tax slabs (India)."""
    GST_0 = "0"
    GST_5 = "5"
    GST_12 = "12"
    GST_18 = "18"
    GST_28 = "28"


# ── Sub-models ───────────────────────────────────────────────────


class PricingModel(BaseModel):
    """Pricing breakdown for an item."""
    cost_price: float = Field(..., ge=0, description="Purchase / cost price")
    selling_price: float = Field(..., ge=0, description="Selling price (excl. tax)")
    mrp: Optional[float] = Field(None, ge=0, description="Maximum retail price")
    wholesale_price: Optional[float] = Field(None, ge=0, description="Bulk / wholesale price")
    min_wholesale_qty: Optional[int] = Field(None, ge=1, description="Min qty for wholesale price")
    tax_rate: TaxSlabEnum = Field(default=TaxSlabEnum.GST_18, description="GST slab")
    hsn_code: Optional[str] = Field(None, max_length=10, description="HSN/SAC code for GST")
    discount_percent: Optional[float] = Field(None, ge=0, le=100, description="Default discount %")


class DimensionsModel(BaseModel):
    """Physical dimensions (optional, for items sold by size)."""
    length: Optional[float] = Field(None, ge=0)
    width: Optional[float] = Field(None, ge=0)
    height: Optional[float] = Field(None, ge=0)
    weight: Optional[float] = Field(None, ge=0, description="Weight in primary unit")
    dimension_unit: Optional[str] = Field(None, description="e.g. mm, cm, inch")


class StockInfoModel(BaseModel):
    """Inventory tracking fields."""
    current_stock: float = Field(default=0, ge=0, description="Current quantity in stock")
    min_stock_level: Optional[float] = Field(None, ge=0, description="Alert when stock falls below this")
    reorder_level: Optional[float] = Field(None, ge=0, description="Reorder trigger level")
    reorder_qty: Optional[float] = Field(None, ge=0, description="Default reorder quantity")
    max_stock_level: Optional[float] = Field(None, ge=0, description="Maximum storage capacity")
    location: Optional[str] = Field(None, max_length=100, description="Warehouse / rack location")


class SupplierRefModel(BaseModel):
    """Reference to a supplier for this item."""
    supplier_name: str = Field(..., min_length=1, max_length=100)
    supplier_id: Optional[str] = None
    supplier_sku: Optional[str] = None
    lead_time_days: Optional[int] = Field(None, ge=0, description="Delivery lead time in days")


# ── Main request schemas ─────────────────────────────────────────


class CreateItemRequest(BaseModel):
    """POST /items — create a new item."""

    # ── Identity ─────────────────────────────────────────────
    name: str = Field(..., min_length=2, max_length=200, description="Item / product name")
    sku: Optional[str] = Field(None, max_length=50, description="Stock Keeping Unit code")
    barcode: Optional[str] = Field(None, max_length=50, description="EAN / UPC barcode")
    description: Optional[str] = Field(None, max_length=1000)

    # ── Classification ───────────────────────────────────────
    category: ItemCategoryEnum
    sub_category: Optional[str] = Field(None, max_length=100, description="Free-text sub-category")
    brand: Optional[str] = Field(None, max_length=100)
    manufacturer: Optional[str] = Field(None, max_length=100)
    model_number: Optional[str] = Field(None, max_length=100)
    tags: Optional[List[str]] = Field(default=[], description="Searchable tags")

    # ── Units ────────────────────────────────────────────────
    unit: UnitOfMeasurement = Field(default=UnitOfMeasurement.PIECE)
    secondary_unit: Optional[UnitOfMeasurement] = Field(None, description="Alt unit (e.g. kg + bag)")
    conversion_factor: Optional[float] = Field(None, gt=0, description="secondary = primary * factor")

    # ── Pricing ──────────────────────────────────────────────
    pricing: PricingModel

    # ── Physical ─────────────────────────────────────────────
    dimensions: Optional[DimensionsModel] = None

    # ── Stock ────────────────────────────────────────────────
    stock: Optional[StockInfoModel] = Field(default_factory=StockInfoModel)

    # ── Supplier ─────────────────────────────────────────────
    suppliers: Optional[List[SupplierRefModel]] = Field(default=[])

    # ── Media ────────────────────────────────────────────────
    images: Optional[List[str]] = Field(default=[], description="Image URLs")

    # ── Status ───────────────────────────────────────────────
    status: ItemStatusEnum = Field(default=ItemStatusEnum.ACTIVE)
    is_sellable: bool = Field(default=True, description="Available for POS sale")
    is_purchasable: bool = Field(default=True, description="Can be purchased from supplier")

    # ── Validators ───────────────────────────────────────────
    @field_validator("sku")
    @classmethod
    def validate_sku(cls, v):
        if v and not re.match(r"^[A-Za-z0-9\-_]+$", v):
            raise ValueError("SKU can only contain letters, numbers, hyphens, and underscores")
        return v.upper() if v else v

    @field_validator("barcode")
    @classmethod
    def validate_barcode(cls, v):
        if v and not v.strip().isdigit():
            raise ValueError("Barcode must be numeric")
        return v


class UpdateItemRequest(BaseModel):
    """PUT /items/{id} — partial update."""

    name: Optional[str] = Field(None, min_length=2, max_length=200)
    sku: Optional[str] = Field(None, max_length=50)
    barcode: Optional[str] = Field(None, max_length=50)
    description: Optional[str] = Field(None, max_length=1000)
    category: Optional[ItemCategoryEnum] = None
    sub_category: Optional[str] = None
    brand: Optional[str] = None
    manufacturer: Optional[str] = None
    model_number: Optional[str] = None
    tags: Optional[List[str]] = None
    unit: Optional[UnitOfMeasurement] = None
    secondary_unit: Optional[UnitOfMeasurement] = None
    conversion_factor: Optional[float] = None
    pricing: Optional[PricingModel] = None
    dimensions: Optional[DimensionsModel] = None
    stock: Optional[StockInfoModel] = None
    suppliers: Optional[List[SupplierRefModel]] = None
    images: Optional[List[str]] = None
    status: Optional[ItemStatusEnum] = None
    is_sellable: Optional[bool] = None
    is_purchasable: Optional[bool] = None
