from pydantic import BaseModel




class AppUser(BaseModel):
    name : str
    app_code: str
