from typing import List, Optional
from datetime import datetime
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId

from app._schemas.employee_schema import EmployeeCreate, EmployeeUpdate, EmployeeResponse, EmployeeList
from app.utils.exceptions import NotFoundError, DuplicateError, ValidationError
from app.utils.helpers import serialize_datetime, calculate_pagination


class EmployeeService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.employees_collection = db.employees
        self.stores_collection = db.stores
        self.sales_collection = db.sales

    async def create_employee(self, employee_data: EmployeeCreate) -> EmployeeResponse:
        """Create a new employee"""
        # Check if employee_id already exists
        existing_employee = await self.employees_collection.find_one({"employee_id": employee_data.employee_id})
        if existing_employee:
            raise DuplicateError("Employee with this ID already exists")

        # Check if email already exists (if provided)
        if employee_data.email:
            existing_employee = await self.employees_collection.find_one({"email": employee_data.email})
            if existing_employee:
                raise DuplicateError("Employee with this email already exists")

        employee_doc = {
            **employee_data.dict(),
            "user_id": None,  # Will be set when user account is created
            "hire_date": datetime.utcnow(),
            "is_active": True,
            "created_at": datetime.utcnow()
        }

        result = await self.employees_collection.insert_one(employee_doc)
        created_employee = await self.employees_collection.find_one({"_id": result.inserted_id})
        
        return await self._serialize_employee_with_details(created_employee)

    async def get_employee(self, employee_id: str) -> EmployeeResponse:
        """Get employee by ID"""
        try:
            employee_doc = await self.employees_collection.find_one({"_id": ObjectId(employee_id)})
            if not employee_doc:
                raise NotFoundError("Employee not found")
            return await self._serialize_employee_with_details(employee_doc)
        except Exception as e:
            if isinstance(e, NotFoundError):
                raise e
            raise ValidationError("Invalid employee ID")

    async def get_employee_by_employee_id(self, employee_id: str) -> EmployeeResponse:
        """Get employee by employee_id"""
        employee_doc = await self.employees_collection.find_one({"employee_id": employee_id})
        if not employee_doc:
            raise NotFoundError("Employee not found")
        return await self._serialize_employee_with_details(employee_doc)

    async def update_employee(self, employee_id: str, employee_data: EmployeeUpdate) -> EmployeeResponse:
        """Update employee"""
        try:
            update_data = {k: v for k, v in employee_data.dict().items() if v is not None}
            if not update_data:
                raise ValidationError("No data provided for update")

            result = await self.employees_collection.update_one(
                {"_id": ObjectId(employee_id)},
                {"$set": update_data}
            )

            if result.matched_count == 0:
                raise NotFoundError("Employee not found")

            updated_employee = await self.employees_collection.find_one({"_id": ObjectId(employee_id)})
            return await self._serialize_employee_with_details(updated_employee)
        except Exception as e:
            if isinstance(e, (NotFoundError, ValidationError)):
                raise e
            raise ValidationError("Invalid employee ID")

    async def delete_employee(self, employee_id: str) -> bool:
        """Soft delete employee"""
        try:
            result = await self.employees_collection.update_one(
                {"_id": ObjectId(employee_id)},
                {"$set": {"is_active": False}}
            )
            return result.matched_count > 0
        except:
            return False

    async def list_employees(self, page: int = 1, per_page: int = 20, 
                           store_id: Optional[str] = None,
                           department: Optional[str] = None,
                           search: Optional[str] = None,
                           is_active: Optional[bool] = None) -> EmployeeList:
        """List employees with pagination and filters"""
        skip = (page - 1) * per_page
        query = {}

        if store_id:
            query["$or"] = [
                {"store_id": ObjectId(store_id)},
                {"additional_store_ids": ObjectId(store_id)}
            ]
        
        if department:
            query["department"] = {"$regex": department, "$options": "i"}
            
        if is_active is not None:
            query["is_active"] = is_active
        
        if search:
            query["$or"] = [
                {"first_name": {"$regex": search, "$options": "i"}},
                {"last_name": {"$regex": search, "$options": "i"}},
                {"employee_id": {"$regex": search, "$options": "i"}},
                {"email": {"$regex": search, "$options": "i"}},
                {"position": {"$regex": search, "$options": "i"}}
            ]

        total = await self.employees_collection.count_documents(query)
        
        # Count active and inactive employees
        active_count = await self.employees_collection.count_documents({**query, "is_active": True})
        inactive_count = total - active_count
        
        employees_cursor = self.employees_collection.find(query).sort("created_at", -1).skip(skip).limit(per_page)
        employees = await employees_cursor.to_list(length=per_page)

        serialized_employees = []
        for employee in employees:
            serialized_employees.append(await self._serialize_employee_with_details(employee))

        return EmployeeList(
            employees=serialized_employees,
            active_count=active_count,
            inactive_count=inactive_count,
            **calculate_pagination(page, per_page, total)
        )

    async def get_employee_performance(self, employee_id: str, start_date: Optional[datetime] = None, 
                                     end_date: Optional[datetime] = None):
        """Get employee performance metrics"""
        # Build date query
        date_query = {}
        if start_date:
            date_query["$gte"] = start_date
        if end_date:
            date_query["$lte"] = end_date
        
        # Sales performance pipeline
        pipeline = [
            {
                "$match": {
                    "employee_id": ObjectId(employee_id),
                    **({"sale_date": date_query} if date_query else {})
                }
            },
            {
                "$group": {
                    "_id": None,
                    "total_sales": {"$sum": 1},
                    "total_revenue": {"$sum": "$total_amount"},
                    "average_sale_amount": {"$avg": "$total_amount"}
                }
            }
        ]
        
        performance_result = await self.sales_collection.aggregate(pipeline).to_list(length=1)
        performance = performance_result[0] if performance_result else {
            "total_sales": 0,
            "total_revenue": 0,
            "average_sale_amount": 0
        }

        return {
            "employee_id": employee_id,
            "period": {
                "start_date": start_date.isoformat() if start_date else None,
                "end_date": end_date.isoformat() if end_date else None
            },
            "performance": performance
        }

    async def _serialize_employee_with_details(self, employee_doc: dict) -> EmployeeResponse:
        """Convert employee document to EmployeeResponse with store details"""
        # Get store details
        store = await self.stores_collection.find_one({"_id": employee_doc["store_id"]})
        
        # Calculate full name
        full_name = f"{employee_doc['first_name']} {employee_doc['last_name']}"

        return EmployeeResponse(
            id=employee_doc["_id"],
            user_id=employee_doc.get("user_id"),
            employee_id=employee_doc["employee_id"],
            first_name=employee_doc["first_name"],
            last_name=employee_doc["last_name"],
            full_name=full_name,
            email=employee_doc.get("email"),
            phone=employee_doc["phone"],
            address=employee_doc.get("address"),
            position=employee_doc["position"],
            department=employee_doc.get("department"),
            store_id=employee_doc["store_id"],
            additional_store_ids=employee_doc.get("additional_store_ids", []),
            hire_date=serialize_datetime(employee_doc["hire_date"]),
            salary=employee_doc.get("salary"),
            hourly_rate=employee_doc.get("hourly_rate"),
            commission_rate=employee_doc["commission_rate"],
            is_active=employee_doc["is_active"],
            emergency_contact_name=employee_doc.get("emergency_contact_name"),
            emergency_contact_phone=employee_doc.get("emergency_contact_phone"),
            notes=employee_doc.get("notes"),
            created_at=serialize_datetime(employee_doc["created_at"]),
            store_name=store["name"] if store else None
        )