from pydantic import BaseModel, Field, constr
from enum import Enum
from typing import Optional


class CountryEnum(str, Enum):
    INDIA = "India"
    USA = "United States"
    UK = "United Kingdom"
    CANADA = "Canada"




class Address(BaseModel):
    location: constr(strip_whitespace=True, max_length=100) = Field(
        ..., description="Optional area or landmark near the address"
    )
    pincode: Optional[constr(strip_whitespace=True, min_length=4, max_length=10)] = (
        Field(None, description="Postal code of the address")
    )
    street: Optional[constr(strip_whitespace=True, min_length=5, max_length=200)] = (
        Field(None, description="Street address")
    )
    district: Optional[constr(strip_whitespace=True, min_length=2, max_length=100)] = (
        Field(None, description="District or city name")
    )
    state: Optional[constr(strip_whitespace=True, min_length=2, max_length=100)] = (
        Field(None, description="State or province name")
    )
    country: Optional[CountryEnum] = Field(None, description="Country")

    class Config:
        anystr_strip_whitespace = True
        min_anystr_length = 1
        max_anystr_length = 200
