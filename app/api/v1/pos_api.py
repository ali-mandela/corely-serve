from fastapi import APIRouter


pos = APIRouter()


@pos.get("")
async def res():
    return {"POS": "POS"}
