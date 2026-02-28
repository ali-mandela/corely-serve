from pydantic import BaseModel


class Item(BaseModel):
    item_id: str
    tax_: str
    discount: str
    


class POSSchema(BaseModel):
    customer: any
    job_status: str
    payment_status: str
    items: list[Item]
    total_amount: str
