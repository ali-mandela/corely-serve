from fastapi import Depends
from app.core.config.database import DatabaseManager


class appAdminService:
    def __init__(self, db=Depends(DatabaseManager.get_database())):
        self.collection = db["app_admins"]

    def generate_admin_token():
        pass