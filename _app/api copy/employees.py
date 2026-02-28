from typing import Optional, List
from datetime import datetime, timezone, date
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId
from decimal import Decimal

from app._core.database import get_database
from app._schemas.employee_schema import (
    EmployeeCreate,
    EmployeeUpdate,
    EmployeeResponse,
    EmployeeListResponse,
    EmployeeStats,
    EmployeePerformance,
    AttendanceRecord,
    EmployeeScheduleUpdate,
    EmployeeRoleUpdate,
    EmployeeStatusUpdate,
    EmployeeBulkAction,
    EmployeePayrollUpdate,
    EmployeeTransfer,
    EmployeeStatus,
    EmploymentType,
    ShiftType,
)
from app._schemas.user_schema import UserResponse, UserCreate
from app._services.auth_service import get_current_user, get_auth_service, AuthService
from app.utils.exceptions import NotFoundError, DuplicateError, ValidationError
from app._models.user import UserRole
from app._core.security import get_password_hash

# ABAC and audit imports
from app._core.abac.decorators import require_permission, require_read_permission, require_write_permission
from app._core.tenant_isolation import get_tenant_context, TenantContext, require_tenant_isolation
from app._core.audit.logger import log_data_event

router = APIRouter()


class EmployeeService:
    """Production-grade Employee Service with comprehensive functionality"""

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.employees_collection = db.employees
        self.users_collection = db.users
        self.stores_collection = db.stores
        self.sales_collection = db.sales
        self.attendance_collection = db.attendance
        self.performance_collection = db.employee_performance

    async def create_employee(self, employee_data: EmployeeCreate, organization_id: str) -> EmployeeResponse:
        """Create a new employee with user account"""

        # Check if employee ID is unique within organization
        existing_employee = await self.employees_collection.find_one({
            "employee_id": employee_data.employee_id,
            "organization_id": ObjectId(organization_id)
        })
        if existing_employee:
            raise DuplicateError("Employee ID already exists in this organization")

        # Check if email is unique globally
        existing_user = await self.users_collection.find_one({"email": employee_data.email})
        if existing_user:
            raise DuplicateError("Email already exists")

        # Check if username is unique within organization
        existing_username = await self.users_collection.find_one({
            "username": employee_data.username,
            "organization_id": ObjectId(organization_id)
        })
        if existing_username:
            raise DuplicateError("Username already exists in this organization")

        # Validate stores exist
        primary_store = await self.stores_collection.find_one({
            "_id": ObjectId(employee_data.primary_store_id),
            "organization_id": ObjectId(organization_id)
        })
        if not primary_store:
            raise NotFoundError("Primary store not found")

        for store_id in employee_data.additional_store_ids:
            store = await self.stores_collection.find_one({
                "_id": ObjectId(store_id),
                "organization_id": ObjectId(organization_id)
            })
            if not store:
                raise NotFoundError(f"Store {store_id} not found")

        # Validate manager if provided
        if employee_data.manager_id:
            manager = await self.users_collection.find_one({
                "_id": ObjectId(employee_data.manager_id),
                "organization_id": ObjectId(organization_id),
                "role": {"$in": ["manager", "admin", "super_admin"]}
            })
            if not manager:
                raise NotFoundError("Manager not found or invalid role")

        # Create user account first
        user_data = UserCreate(
            username=employee_data.username,
            email=employee_data.email,
            phone=employee_data.phone,
            password=employee_data.password,
            full_name=f"{employee_data.first_name} {employee_data.last_name}",
            role=employee_data.role,
            organization_id=organization_id,
            store_ids=[employee_data.primary_store_id] + employee_data.additional_store_ids,
            default_store_id=employee_data.primary_store_id,
            permissions=employee_data.permissions
        )

        # Hash password and create user
        hashed_password = get_password_hash(user_data.password)
        user_doc = {
            "username": user_data.username,
            "email": user_data.email,
            "phone": user_data.phone,
            "hashed_password": hashed_password,
            "full_name": user_data.full_name,
            "role": user_data.role.value,
            "organization_id": ObjectId(organization_id),
            "store_ids": [ObjectId(sid) for sid in user_data.store_ids],
            "default_store_id": ObjectId(user_data.default_store_id),
            "permissions": user_data.permissions,
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        }

        user_result = await self.users_collection.insert_one(user_doc)
        user_id = user_result.inserted_id

        # Create employee record
        employee_doc = {
            "user_id": user_id,
            "organization_id": ObjectId(organization_id),
            "employee_id": employee_data.employee_id,
            "first_name": employee_data.first_name,
            "last_name": employee_data.last_name,
            "full_name": f"{employee_data.first_name} {employee_data.last_name}",
            "email": employee_data.email,
            "phone": employee_data.phone,
            "date_of_birth": employee_data.date_of_birth,
            "gender": employee_data.gender,
            "address": employee_data.address.dict() if employee_data.address else None,

            # Employment details
            "hire_date": employee_data.hire_date,
            "employment_type": employee_data.employment_type.value,
            "position": employee_data.position,
            "department": employee_data.department,
            "manager_id": ObjectId(employee_data.manager_id) if employee_data.manager_id else None,
            "status": EmployeeStatus.ACTIVE.value,

            # Store assignment
            "primary_store_id": ObjectId(employee_data.primary_store_id),
            "additional_store_ids": [ObjectId(sid) for sid in employee_data.additional_store_ids],

            # Payroll information
            "payroll_info": employee_data.payroll_info.dict(),

            # Schedule
            "work_schedule": [schedule.dict() for schedule in employee_data.work_schedule],
            "shift_type": employee_data.shift_type.value,

            # Personal information
            "emergency_contacts": [contact.dict() for contact in employee_data.emergency_contacts],
            "notes": employee_data.notes,

            # Metadata
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        }

        result = await self.employees_collection.insert_one(employee_doc)
        created_employee = await self.employees_collection.find_one({"_id": result.inserted_id})

        return await self._serialize_employee(created_employee)

    async def get_employee_by_id(self, employee_id: str, organization_id: str) -> EmployeeResponse:
        """Get employee by ID"""
        employee = await self.employees_collection.find_one({
            "_id": ObjectId(employee_id),
            "organization_id": ObjectId(organization_id)
        })
        if not employee:
            raise NotFoundError("Employee not found")

        return await self._serialize_employee(employee)

    async def update_employee(self, employee_id: str, employee_data: EmployeeUpdate, organization_id: str) -> EmployeeResponse:
        """Update employee information"""
        employee = await self.employees_collection.find_one({
            "_id": ObjectId(employee_id),
            "organization_id": ObjectId(organization_id)
        })
        if not employee:
            raise NotFoundError("Employee not found")

        # Prepare update data
        update_data = {k: v for k, v in employee_data.dict(exclude_unset=True).items() if v is not None}

        if update_data:
            # Handle nested objects
            if "address" in update_data:
                update_data["address"] = update_data["address"].dict()
            if "payroll_info" in update_data:
                update_data["payroll_info"] = update_data["payroll_info"].dict()
            if "work_schedule" in update_data:
                update_data["work_schedule"] = [schedule.dict() for schedule in update_data["work_schedule"]]
            if "emergency_contacts" in update_data:
                update_data["emergency_contacts"] = [contact.dict() for contact in update_data["emergency_contacts"]]

            # Update full name if first or last name changed
            if "first_name" in update_data or "last_name" in update_data:
                first_name = update_data.get("first_name", employee["first_name"])
                last_name = update_data.get("last_name", employee["last_name"])
                update_data["full_name"] = f"{first_name} {last_name}"

            update_data["updated_at"] = datetime.now(timezone.utc)

            await self.employees_collection.update_one(
                {"_id": ObjectId(employee_id)},
                {"$set": update_data}
            )

            # Update corresponding user record if needed
            user_update = {}
            if "email" in update_data:
                user_update["email"] = update_data["email"]
            if "phone" in update_data:
                user_update["phone"] = update_data["phone"]
            if "role" in update_data:
                user_update["role"] = update_data["role"].value
            if "permissions" in update_data:
                user_update["permissions"] = update_data["permissions"]
            if "full_name" in update_data:
                user_update["full_name"] = update_data["full_name"]

            if user_update:
                user_update["updated_at"] = datetime.now(timezone.utc)
                await self.users_collection.update_one(
                    {"_id": employee["user_id"]},
                    {"$set": user_update}
                )

        updated_employee = await self.employees_collection.find_one({"_id": ObjectId(employee_id)})
        return await self._serialize_employee(updated_employee)

    async def delete_employee(self, employee_id: str, organization_id: str) -> bool:
        """Soft delete employee"""
        result = await self.employees_collection.update_one(
            {"_id": ObjectId(employee_id), "organization_id": ObjectId(organization_id)},
            {"$set": {
                "is_active": False,
                "status": EmployeeStatus.TERMINATED.value,
                "updated_at": datetime.now(timezone.utc)
            }}
        )

        if result.modified_count > 0:
            # Also deactivate user account
            employee = await self.employees_collection.find_one({"_id": ObjectId(employee_id)})
            if employee and employee.get("user_id"):
                await self.users_collection.update_one(
                    {"_id": employee["user_id"]},
                    {"$set": {"is_active": False, "updated_at": datetime.now(timezone.utc)}}
                )

        return result.modified_count > 0

    async def list_employees(self, organization_id: str, page: int = 1, per_page: int = 20,
                           status: Optional[EmployeeStatus] = None, department: Optional[str] = None,
                           store_id: Optional[str] = None, search: Optional[str] = None) -> EmployeeListResponse:
        """List employees with pagination and filters"""
        query = {"organization_id": ObjectId(organization_id), "is_active": True}

        if status:
            query["status"] = status.value
        if department:
            query["department"] = {"$regex": department, "$options": "i"}
        if store_id:
            query["$or"] = [
                {"primary_store_id": ObjectId(store_id)},
                {"additional_store_ids": ObjectId(store_id)}
            ]
        if search:
            query["$or"] = [
                {"employee_id": {"$regex": search, "$options": "i"}},
                {"first_name": {"$regex": search, "$options": "i"}},
                {"last_name": {"$regex": search, "$options": "i"}},
                {"full_name": {"$regex": search, "$options": "i"}},
                {"email": {"$regex": search, "$options": "i"}},
                {"position": {"$regex": search, "$options": "i"}}
            ]

        total = await self.employees_collection.count_documents(query)
        skip = (page - 1) * per_page

        employees_cursor = self.employees_collection.find(query).skip(skip).limit(per_page).sort("created_at", -1)
        employees = await employees_cursor.to_list(length=per_page)

        serialized_employees = []
        for employee in employees:
            serialized_employees.append(await self._serialize_employee(employee))

        return EmployeeListResponse(
            employees=serialized_employees,
            total=total,
            page=page,
            per_page=per_page,
            pages=(total + per_page - 1) // per_page
        )

    async def get_employee_stats(self, employee_id: str, organization_id: str) -> EmployeeStats:
        """Get comprehensive employee statistics"""
        employee = await self.employees_collection.find_one({
            "_id": ObjectId(employee_id),
            "organization_id": ObjectId(organization_id)
        })
        if not employee:
            raise NotFoundError("Employee not found")

        # Sales statistics
        sales_pipeline = [
            {"$match": {
                "employee_id": ObjectId(employee_id),
                "organization_id": ObjectId(organization_id)
            }},
            {"$group": {
                "_id": None,
                "total_sales": {"$sum": "$total_amount"},
                "total_orders": {"$sum": 1},
                "avg_order_value": {"$avg": "$total_amount"}
            }}
        ]
        sales_stats = await self.sales_collection.aggregate(sales_pipeline).to_list(1)
        sales_data = sales_stats[0] if sales_stats else {
            "total_sales": 0, "total_orders": 0, "avg_order_value": 0
        }

        # Attendance calculation
        attendance_pipeline = [
            {"$match": {
                "employee_id": employee["employee_id"],
                "date": {"$gte": date.today().replace(day=1)}  # Current month
            }},
            {"$group": {
                "_id": None,
                "total_hours": {"$sum": "$hours_worked"},
                "present_days": {"$sum": {"$cond": [{"$eq": ["$status", "present"]}, 1, 0]}},
                "total_days": {"$sum": 1}
            }}
        ]
        attendance_stats = await self.attendance_collection.aggregate(attendance_pipeline).to_list(1)
        attendance_data = attendance_stats[0] if attendance_stats else {
            "total_hours": 0, "present_days": 0, "total_days": 1
        }

        # Calculate commission earned
        payroll_info = employee.get("payroll_info", {})
        commission_rate = float(payroll_info.get("commission_rate", 0))
        commission_earned = Decimal(str(sales_data["total_sales"])) * Decimal(str(commission_rate))

        return EmployeeStats(
            employee_id=employee["employee_id"],
            employee_name=employee["full_name"],
            total_sales=Decimal(str(sales_data["total_sales"])),
            total_orders=sales_data["total_orders"],
            avg_order_value=Decimal(str(sales_data["avg_order_value"])),
            performance_score=85.0,  # Would be calculated based on various metrics
            attendance_rate=float(attendance_data["present_days"]) / float(attendance_data["total_days"]) * 100,
            hours_worked_this_month=float(attendance_data["total_hours"]),
            commission_earned=commission_earned,
            customer_satisfaction=4.2  # Would come from customer reviews
        )

    async def _serialize_employee(self, employee_doc: dict) -> EmployeeResponse:
        """Serialize employee document to response model"""
        # Get manager name if exists
        manager_name = None
        if employee_doc.get("manager_id"):
            manager = await self.users_collection.find_one({"_id": employee_doc["manager_id"]})
            if manager:
                manager_name = manager.get("full_name") or manager.get("username")

        # Get store names
        primary_store_name = ""
        primary_store = await self.stores_collection.find_one({"_id": employee_doc["primary_store_id"]})
        if primary_store:
            primary_store_name = primary_store["name"]

        additional_store_names = []
        for store_id in employee_doc.get("additional_store_ids", []):
            store = await self.stores_collection.find_one({"_id": store_id})
            if store:
                additional_store_names.append(store["name"])

        # Get user data
        user_doc = await self.users_collection.find_one({"_id": employee_doc["user_id"]})

        return EmployeeResponse(
            id=str(employee_doc["_id"]),
            user_id=str(employee_doc["user_id"]),
            organization_id=str(employee_doc["organization_id"]),
            employee_id=employee_doc["employee_id"],
            first_name=employee_doc["first_name"],
            last_name=employee_doc["last_name"],
            full_name=employee_doc["full_name"],
            email=employee_doc["email"],
            phone=employee_doc["phone"],
            date_of_birth=employee_doc.get("date_of_birth"),
            gender=employee_doc.get("gender"),
            address=employee_doc.get("address"),
            hire_date=employee_doc["hire_date"],
            employment_type=EmploymentType(employee_doc["employment_type"]),
            position=employee_doc["position"],
            department=employee_doc["department"],
            manager_id=str(employee_doc["manager_id"]) if employee_doc.get("manager_id") else None,
            manager_name=manager_name,
            status=EmployeeStatus(employee_doc["status"]),
            primary_store_id=str(employee_doc["primary_store_id"]),
            primary_store_name=primary_store_name,
            additional_store_ids=[str(sid) for sid in employee_doc.get("additional_store_ids", [])],
            additional_store_names=additional_store_names,
            role=UserRole(user_doc["role"]) if user_doc else UserRole.EMPLOYEE,
            username=user_doc["username"] if user_doc else "",
            permissions=user_doc.get("permissions", []) if user_doc else [],
            is_active=employee_doc["is_active"],
            payroll_info=employee_doc["payroll_info"],
            work_schedule=employee_doc.get("work_schedule", []),
            shift_type=ShiftType(employee_doc["shift_type"]),
            emergency_contacts=employee_doc.get("emergency_contacts", []),
            notes=employee_doc.get("notes"),
            created_at=employee_doc["created_at"],
            updated_at=employee_doc["updated_at"],
            last_login=user_doc.get("last_login") if user_doc else None
        )


async def get_employee_service(db: AsyncIOMotorDatabase = Depends(get_database)) -> EmployeeService:
    """Get employee service instance"""
    return EmployeeService(db)


# API Endpoints
@router.post("/", response_model=EmployeeResponse, status_code=status.HTTP_201_CREATED)
@require_permission("employee", "create")
@require_tenant_isolation()
async def create_employee(
    request: Request,
    employee_data: EmployeeCreate,
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    employee_service: EmployeeService = Depends(get_employee_service)
):
    """Create a new employee - Admin/Super Admin only"""
    try:
        # Validate role permissions using ABAC
        if current_user.role == UserRole.ADMIN and employee_data.role not in [UserRole.EMPLOYEE, UserRole.MANAGER]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admins can only create employees and managers"
            )

        # Only super admins can create other admins
        if employee_data.role == UserRole.ADMIN and current_user.role != UserRole.SUPER_ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only super admins can create admin users"
            )


        employee = await employee_service.create_employee(employee_data, tenant_context.tenant_id)

        await log_data_event(
            user_id=current_user.id,
            operation="create",
            resource_type="employee",
            resource_id=employee.id,
            success=True,
            tenant_id=tenant_context.tenant_id
        )

        return employee
    except DuplicateError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/", response_model=EmployeeListResponse)
@require_read_permission("employee")
@require_tenant_isolation()
async def list_employees(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status: Optional[EmployeeStatus] = Query(None),
    department: Optional[str] = Query(None),
    store_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    employee_service: EmployeeService = Depends(get_employee_service)
):
    """List employees with pagination and filters"""
    return await employee_service.list_employees(
        tenant_context.tenant_id, page, per_page, status, department, store_id, search
    )


@router.get("/{employee_id}", response_model=EmployeeResponse)
@require_read_permission("employee")
@require_tenant_isolation()
async def get_employee(
    employee_id: str,
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    employee_service: EmployeeService = Depends(get_employee_service)
):
    """Get employee by ID"""
    try:
        return await employee_service.get_employee_by_id(employee_id, tenant_context.tenant_id)
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.put("/{employee_id}", response_model=EmployeeResponse)
@require_permission("employee", "update")
@require_tenant_isolation()
async def update_employee(
    employee_id: str,
    employee_data: EmployeeUpdate,
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    employee_service: EmployeeService = Depends(get_employee_service)
):
    """Update employee - Admin/Super Admin/Manager only"""
    try:

        employee = await employee_service.update_employee(employee_id, employee_data, tenant_context.tenant_id)

        await log_data_event(
            user_id=current_user.id,
            operation="update",
            resource_type="employee",
            resource_id=employee_id,
            success=True,
            tenant_id=tenant_context.tenant_id
        )

        return employee
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.delete("/{employee_id}")
@require_permission("employee", "delete")
@require_tenant_isolation()
async def delete_employee(
    employee_id: str,
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    employee_service: EmployeeService = Depends(get_employee_service)
):
    """Delete employee - Admin/Super Admin only"""
    try:

        success = await employee_service.delete_employee(employee_id, tenant_context.tenant_id)
        if not success:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Employee not found")

        await log_data_event(
            user_id=current_user.id,
            operation="delete",
            resource_type="employee",
            resource_id=employee_id,
            success=True,
            tenant_id=tenant_context.tenant_id
        )

        return {"message": "Employee deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/{employee_id}/stats", response_model=EmployeeStats)
@require_read_permission("employee")
@require_tenant_isolation()
async def get_employee_stats(
    employee_id: str,
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    employee_service: EmployeeService = Depends(get_employee_service)
):
    """Get employee statistics and performance metrics"""
    try:
        return await employee_service.get_employee_stats(employee_id, tenant_context.tenant_id)
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.put("/{employee_id}/role", response_model=EmployeeResponse)
@require_permission("employee", "update")
@require_tenant_isolation()
async def update_employee_role(
    employee_id: str,
    role_data: EmployeeRoleUpdate,
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    employee_service: EmployeeService = Depends(get_employee_service)
):
    """Update employee role and permissions - Admin/Super Admin only"""
    try:
        # Validate role permissions
        if current_user.role == UserRole.ADMIN and role_data.role not in [UserRole.EMPLOYEE, UserRole.MANAGER]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admins can only assign employee and manager roles"
            )

        if role_data.role == UserRole.ADMIN and current_user.role != UserRole.SUPER_ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only super admins can assign admin role"
            )


        employee_update = EmployeeUpdate(role=role_data.role, permissions=role_data.permissions)
        employee = await employee_service.update_employee(employee_id, employee_update, tenant_context.tenant_id)

        await log_data_event(
            user_id=current_user.id,
            operation="update_role",
            resource_type="employee",
            resource_id=employee_id,
            success=True,
            tenant_id=tenant_context.tenant_id,
            metadata={"new_role": role_data.role.value, "reason": role_data.reason}
        )

        return employee
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.put("/{employee_id}/status", response_model=EmployeeResponse)
@require_permission("employee", "update")
@require_tenant_isolation()
async def update_employee_status(
    employee_id: str,
    status_data: EmployeeStatusUpdate,
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    employee_service: EmployeeService = Depends(get_employee_service)
):
    """Update employee status - Admin/Super Admin only"""
    try:
        employee_update = EmployeeUpdate(status=status_data.status)
        employee = await employee_service.update_employee(employee_id, employee_update, tenant_context.tenant_id)

        await log_data_event(
            user_id=current_user.id,
            operation="update_status",
            resource_type="employee",
            resource_id=employee_id,
            success=True,
            tenant_id=tenant_context.tenant_id,
            metadata={
                "new_status": status_data.status.value,
                "effective_date": status_data.effective_date.isoformat(),
                "reason": status_data.reason
            }
        )

        return employee
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.put("/{employee_id}/schedule", response_model=EmployeeResponse)
@require_permission("employee", "update")
@require_tenant_isolation()
async def update_employee_schedule(
    employee_id: str,
    schedule_data: EmployeeScheduleUpdate,
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    employee_service: EmployeeService = Depends(get_employee_service)
):
    """Update employee work schedule - Admin/Super Admin/Manager only"""
    try:
        employee_update = EmployeeUpdate(
            work_schedule=schedule_data.work_schedule,
            shift_type=schedule_data.shift_type
        )
        employee = await employee_service.update_employee(employee_id, employee_update, tenant_context.tenant_id)

        await log_data_event(
            user_id=current_user.id,
            operation="update_schedule",
            resource_type="employee",
            resource_id=employee_id,
            success=True,
            tenant_id=tenant_context.tenant_id,
            metadata={"effective_date": schedule_data.effective_date.isoformat()}
        )

        return employee
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.put("/{employee_id}/payroll", response_model=EmployeeResponse)
@require_permission("employee", "update")
@require_tenant_isolation()
async def update_employee_payroll(
    employee_id: str,
    payroll_data: EmployeePayrollUpdate,
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    employee_service: EmployeeService = Depends(get_employee_service)
):
    """Update employee payroll information - Admin/Super Admin only"""
    try:
        employee_update = EmployeeUpdate(payroll_info=payroll_data.payroll_info)
        employee = await employee_service.update_employee(employee_id, employee_update, tenant_context.tenant_id)

        await log_data_event(
            user_id=current_user.id,
            operation="update_payroll",
            resource_type="employee",
            resource_id=employee_id,
            success=True,
            tenant_id=tenant_context.tenant_id,
            metadata={
                "effective_date": payroll_data.effective_date.isoformat(),
                "reason": payroll_data.reason
            }
        )

        return employee
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# Self-service endpoints for employees
@router.get("/me/profile", response_model=EmployeeResponse)
async def get_my_profile(
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    employee_service: EmployeeService = Depends(get_employee_service)
):
    """Get current user's employee profile"""
    try:
        # Find employee by user_id
        employee = await employee_service.employees_collection.find_one({
            "user_id": ObjectId(current_user.id),
            "organization_id": ObjectId(tenant_context.tenant_id)
        })
        if not employee:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Employee profile not found")

        return await employee_service._serialize_employee(employee)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.put("/me/profile")
async def update_my_profile(
    profile_data: dict,
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    employee_service: EmployeeService = Depends(get_employee_service)
):
    """Update current user's employee profile (limited fields)"""
    try:
        # Find employee by user_id
        employee = await employee_service.employees_collection.find_one({
            "user_id": ObjectId(current_user.id),
            "organization_id": ObjectId(tenant_context.tenant_id)
        })
        if not employee:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Employee profile not found")

        # Only allow updating certain fields
        allowed_fields = ["phone", "address", "emergency_contacts"]
        update_data = {k: v for k, v in profile_data.items() if k in allowed_fields}

        if update_data:
            update_data["updated_at"] = datetime.now(timezone.utc)
            await employee_service.employees_collection.update_one(
                {"_id": employee["_id"]},
                {"$set": update_data}
            )

        return {"message": "Profile updated successfully"}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# Performance and Attendance Management
@router.post("/{employee_id}/attendance", response_model=AttendanceRecord)
@require_permission("employee", "update")
@require_tenant_isolation()
async def record_attendance(
    employee_id: str,
    attendance_data: AttendanceRecord,
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    employee_service: EmployeeService = Depends(get_employee_service)
):
    """Record employee attendance"""
    try:
        # Verify employee exists
        employee = await employee_service.employees_collection.find_one({
            "_id": ObjectId(employee_id),
            "organization_id": ObjectId(tenant_context.tenant_id)
        })
        if not employee:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Employee not found")

        # Create attendance record
        attendance_doc = {
            "employee_id": employee["employee_id"],
            "employee_object_id": ObjectId(employee_id),
            "organization_id": ObjectId(tenant_context.tenant_id),
            "date": attendance_data.date,
            "check_in": attendance_data.check_in,
            "check_out": attendance_data.check_out,
            "break_duration": attendance_data.break_duration,
            "hours_worked": attendance_data.hours_worked,
            "overtime_hours": attendance_data.overtime_hours,
            "status": attendance_data.status,
            "notes": attendance_data.notes,
            "recorded_by": ObjectId(current_user.id),
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        }

        # Check for existing record on same date
        existing = await employee_service.attendance_collection.find_one({
            "employee_id": employee["employee_id"],
            "date": attendance_data.date
        })

        if existing:
            # Update existing record
            await employee_service.attendance_collection.update_one(
                {"_id": existing["_id"]},
                {"$set": attendance_doc}
            )
            record_id = existing["_id"]
        else:
            # Create new record
            result = await employee_service.attendance_collection.insert_one(attendance_doc)
            record_id = result.inserted_id

        await log_data_event(
            user_id=current_user.id,
            operation="record_attendance",
            resource_type="attendance",
            resource_id=str(record_id),
            success=True,
            tenant_id=tenant_context.tenant_id
        )

        return attendance_data
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/{employee_id}/attendance", response_model=List[AttendanceRecord])
@require_read_permission("employee")
@require_tenant_isolation()
async def get_employee_attendance(
    employee_id: str,
    start_date: Optional[date] = Query(None),
    end_date: Optional[date] = Query(None),
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    employee_service: EmployeeService = Depends(get_employee_service)
):
    """Get employee attendance records"""
    try:
        # Verify employee exists
        employee = await employee_service.employees_collection.find_one({
            "_id": ObjectId(employee_id),
            "organization_id": ObjectId(tenant_context.tenant_id)
        })
        if not employee:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Employee not found")

        # Build query
        query = {
            "employee_id": employee["employee_id"],
            "organization_id": ObjectId(tenant_context.tenant_id)
        }

        if start_date or end_date:
            date_filter = {}
            if start_date:
                date_filter["$gte"] = start_date
            if end_date:
                date_filter["$lte"] = end_date
            query["date"] = date_filter

        # Get attendance records
        records = await employee_service.attendance_collection.find(query).sort("date", -1).to_list(100)

        return [AttendanceRecord(**record) for record in records]
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/{employee_id}/performance", response_model=EmployeePerformance)
@require_permission("employee", "update")
@require_tenant_isolation()
async def record_performance(
    employee_id: str,
    performance_data: EmployeePerformance,
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    employee_service: EmployeeService = Depends(get_employee_service)
):
    """Record employee performance evaluation"""
    try:
        # Verify employee exists
        employee = await employee_service.employees_collection.find_one({
            "_id": ObjectId(employee_id),
            "organization_id": ObjectId(tenant_context.tenant_id)
        })
        if not employee:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Employee not found")

        # Create performance record
        performance_doc = {
            "employee_id": employee["employee_id"],
            "employee_object_id": ObjectId(employee_id),
            "organization_id": ObjectId(tenant_context.tenant_id),
            "period_start": performance_data.period_start,
            "period_end": performance_data.period_end,
            "sales_target": float(performance_data.sales_target) if performance_data.sales_target else None,
            "sales_achieved": float(performance_data.sales_achieved),
            "orders_completed": performance_data.orders_completed,
            "customer_reviews": performance_data.customer_reviews,
            "avg_customer_rating": performance_data.avg_customer_rating,
            "attendance_days": performance_data.attendance_days,
            "total_working_days": performance_data.total_working_days,
            "goals_met": performance_data.goals_met,
            "total_goals": performance_data.total_goals,
            "manager_rating": performance_data.manager_rating,
            "notes": performance_data.notes,
            "evaluated_by": ObjectId(current_user.id),
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        }

        result = await employee_service.performance_collection.insert_one(performance_doc)

        await log_data_event(
            user_id=current_user.id,
            operation="record_performance",
            resource_type="performance",
            resource_id=str(result.inserted_id),
            success=True,
            tenant_id=tenant_context.tenant_id
        )

        return performance_data
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/{employee_id}/performance", response_model=List[EmployeePerformance])
@require_read_permission("employee")
@require_tenant_isolation()
async def get_employee_performance(
    employee_id: str,
    limit: int = Query(10, ge=1, le=50),
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    employee_service: EmployeeService = Depends(get_employee_service)
):
    """Get employee performance records"""
    try:
        # Verify employee exists
        employee = await employee_service.employees_collection.find_one({
            "_id": ObjectId(employee_id),
            "organization_id": ObjectId(tenant_context.tenant_id)
        })
        if not employee:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Employee not found")

        # Get performance records
        records = await employee_service.performance_collection.find({
            "employee_id": employee["employee_id"],
            "organization_id": ObjectId(tenant_context.tenant_id)
        }).sort("period_end", -1).limit(limit).to_list(limit)

        return [EmployeePerformance(**record) for record in records]
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/transfer", response_model=dict)
@require_permission("employee", "update")
@require_tenant_isolation()
async def transfer_employee(
    transfer_data: EmployeeTransfer,
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    employee_service: EmployeeService = Depends(get_employee_service)
):
    """Transfer employee to different store/manager"""
    try:
        # Verify employee exists
        employee = await employee_service.employees_collection.find_one({
            "_id": ObjectId(transfer_data.employee_id),
            "organization_id": ObjectId(tenant_context.tenant_id)
        })
        if not employee:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Employee not found")

        # Verify new store exists
        new_store = await employee_service.stores_collection.find_one({
            "_id": ObjectId(transfer_data.new_primary_store_id),
            "organization_id": ObjectId(tenant_context.tenant_id)
        })
        if not new_store:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="New store not found")

        # Verify new manager if provided
        if transfer_data.new_manager_id:
            new_manager = await employee_service.users_collection.find_one({
                "_id": ObjectId(transfer_data.new_manager_id),
                "organization_id": ObjectId(tenant_context.tenant_id),
                "role": {"$in": ["manager", "admin", "super_admin"]}
            })
            if not new_manager:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="New manager not found")

        # Update employee record
        update_data = {
            "primary_store_id": ObjectId(transfer_data.new_primary_store_id),
            "additional_store_ids": [ObjectId(sid) for sid in transfer_data.new_additional_store_ids],
            "updated_at": datetime.now(timezone.utc)
        }

        if transfer_data.new_manager_id:
            update_data["manager_id"] = ObjectId(transfer_data.new_manager_id)

        await employee_service.employees_collection.update_one(
            {"_id": ObjectId(transfer_data.employee_id)},
            {"$set": update_data}
        )

        # Update user's store assignments
        user_store_ids = [transfer_data.new_primary_store_id] + transfer_data.new_additional_store_ids
        await employee_service.users_collection.update_one(
            {"_id": employee["user_id"]},
            {"$set": {
                "store_ids": [ObjectId(sid) for sid in user_store_ids],
                "default_store_id": ObjectId(transfer_data.new_primary_store_id),
                "updated_at": datetime.now(timezone.utc)
            }}
        )

        await log_data_event(
            user_id=current_user.id,
            operation="transfer",
            resource_type="employee",
            resource_id=transfer_data.employee_id,
            success=True,
            tenant_id=tenant_context.tenant_id,
            metadata={
                "new_store_id": transfer_data.new_primary_store_id,
                "transfer_date": transfer_data.transfer_date.isoformat(),
                "reason": transfer_data.reason
            }
        )

        return {"message": "Employee transferred successfully"}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/bulk-action", response_model=dict)
@require_permission("employee", "update")
@require_tenant_isolation()
async def bulk_employee_action(
    bulk_data: EmployeeBulkAction,
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    employee_service: EmployeeService = Depends(get_employee_service)
):
    """Perform bulk actions on multiple employees"""
    try:
        # Verify all employees exist
        valid_employees = []
        for employee_id in bulk_data.employee_ids:
            employee = await employee_service.employees_collection.find_one({
                "_id": ObjectId(employee_id),
                "organization_id": ObjectId(tenant_context.tenant_id)
            })
            if employee:
                valid_employees.append(employee_id)

        if not valid_employees:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No valid employees found")

        results = {"processed": 0, "failed": 0, "errors": []}

        for employee_id in valid_employees:
            try:
                if bulk_data.action == "activate":
                    await employee_service.employees_collection.update_one(
                        {"_id": ObjectId(employee_id)},
                        {"$set": {"status": EmployeeStatus.ACTIVE.value, "is_active": True}}
                    )
                elif bulk_data.action == "deactivate":
                    await employee_service.employees_collection.update_one(
                        {"_id": ObjectId(employee_id)},
                        {"$set": {"status": EmployeeStatus.INACTIVE.value, "is_active": False}}
                    )
                elif bulk_data.action == "update_role":
                    new_role = bulk_data.parameters.get("role")
                    if new_role:
                        await employee_service.employees_collection.update_one(
                            {"_id": ObjectId(employee_id)},
                            {"$set": {"role": new_role}}
                        )
                        # Also update user role
                        employee = await employee_service.employees_collection.find_one({"_id": ObjectId(employee_id)})
                        if employee:
                            await employee_service.users_collection.update_one(
                                {"_id": employee["user_id"]},
                                {"$set": {"role": new_role}}
                            )

                results["processed"] += 1
            except Exception as e:
                results["failed"] += 1
                results["errors"].append(f"Employee {employee_id}: {str(e)}")

        await log_data_event(
            user_id=current_user.id,
            operation="bulk_action",
            resource_type="employee",
            resource_id="multiple",
            success=True,
            tenant_id=tenant_context.tenant_id,
            metadata={
                "action": bulk_data.action,
                "employee_count": len(valid_employees),
                "processed": results["processed"],
                "failed": results["failed"]
            }
        )

        return results
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))