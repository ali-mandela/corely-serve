from pydantic import BaseModel


"""
MODULE_MAP = {
    "users": "A",
    "stores": "B",
    "products": "C",
    "inventory": "D",
}

OPERATION_MAP = {
    "GET": "1",  # read
    "PUT": "2",  # update
    "PATCH": "2",
    "DELETE": "3",  # delete
    "POST": "4",  # create
}

"""


class Employee(BaseModel):
    id: int
    name: str
    organization: str
