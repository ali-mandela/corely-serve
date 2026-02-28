from fastapi import APIRouter, Depends, HTTPException, Request, status


store = APIRouter()


@store.get("")
async def get_store(request: Request):
    """Get store information"""
    c = request.state.user
    return {"message": f"Store info for user {c}"}
