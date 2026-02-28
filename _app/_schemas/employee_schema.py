from typing import List, Optional, Dict, Any
from datetime import datetime, date, time
from decimal import Decimal
from pydantic import BaseModel, Field, EmailStr, validator
from enum import Enum

from app._models.user import UserRole


class EmployeeStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    TERMINATED = "terminated"
    ON_LEAVE = "on_leave"
    PROBATION = "probation"


class EmploymentType(str, Enum):
    FULL_TIME = "full_time"
    PART_TIME = "part_time"
    CONTRACT = "contract"
    TEMPORARY = "temporary"
    INTERN = "intern"
    CONSULTANT = "consultant"


class PaymentType(str, Enum):
    SALARY = "salary"
    HOURLY = "hourly"
    COMMISSION = "commission"
    MIXED = "mixed"


class DayOfWeek(str, Enum):
    MONDAY = "monday"
    TUESDAY = "tuesday"
    WEDNESDAY = "wednesday"
    THURSDAY = "thursday"
    FRIDAY = "friday"
    SATURDAY = "saturday"
    SUNDAY = "sunday"


class ShiftType(str, Enum):
    MORNING = "morning"
    AFTERNOON = "afternoon"
    EVENING = "evening"
    NIGHT = "night"
    FLEXIBLE = "flexible"


class Address(BaseModel):
    street: str = Field(..., min_length=1, max_length=200)
    city: str = Field(..., min_length=1, max_length=100)
    state: str = Field(..., min_length=1, max_length=100)
    zip_code: Optional[str] = Field(None, min_length=5, max_length=10)
    country: str = Field(default="USA", min_length=2, max_length=100)

    class Config:
        from_attributes = True


class EmergencyContact(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    relationship: str = Field(..., min_length=1, max_length=50)
    phone: str = Field(..., min_length=10, max_length=15)
    email: Optional[EmailStr] = None
    address: Optional[Address] = None

    class Config:
        from_attributes = True


class WorkSchedule(BaseModel):
    day: DayOfWeek
    start_time: time
    end_time: time
    break_duration: int = Field(30, ge=0, le=120)  # minutes
    is_working_day: bool = True

    class Config:
        from_attributes = True
        json_encoders = {
            time: lambda v: v.strftime('%H:%M')
        }


class PayrollInfo(BaseModel):
    payment_type: PaymentType
    salary: Optional[Decimal] = Field(None, ge=0, max_digits=10, decimal_places=2)
    hourly_rate: Optional[Decimal] = Field(None, ge=0, max_digits=6, decimal_places=2)
    commission_rate: Optional[Decimal] = Field(None, ge=0, le=1, max_digits=5, decimal_places=4)
    overtime_rate: Optional[Decimal] = Field(None, ge=0, max_digits=6, decimal_places=2)
    currency: str = Field(default="USD", min_length=3, max_length=3)
    tax_id: Optional[str] = Field(None, max_length=20)
    bank_account: Optional[str] = Field(None, max_length=50)

    class Config:
        from_attributes = True


class EmployeeCreate(BaseModel):
    # Basic Information
    employee_id: str = Field(..., min_length=1, max_length=20)
    first_name: str = Field(..., min_length=1, max_length=50)
    last_name: str = Field(..., min_length=1, max_length=50)
    email: EmailStr
    phone: str = Field(..., min_length=10, max_length=15)
    date_of_birth: Optional[date] = None
    gender: Optional[str] = Field(None, max_length=20)
    address: Optional[Address] = None

    # Employment Details
    hire_date: date
    employment_type: EmploymentType = EmploymentType.FULL_TIME
    position: str = Field(..., min_length=1, max_length=100)
    department: str = Field(..., min_length=1, max_length=100)
    manager_id: Optional[str] = None

    # Store Assignment
    primary_store_id: str
    additional_store_ids: List[str] = Field(default_factory=list)

    # System Access
    role: UserRole = UserRole.EMPLOYEE
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    permissions: List[str] = Field(default_factory=list)

    # Payroll Information
    payroll_info: PayrollInfo

    # Schedule
    work_schedule: List[WorkSchedule] = Field(default_factory=list)
    shift_type: ShiftType = ShiftType.MORNING

    # Personal Information
    emergency_contacts: List[EmergencyContact] = Field(default_factory=list)
    notes: Optional[str] = Field(None, max_length=1000)

    @validator('employee_id')
    def employee_id_alphanumeric(cls, v):
        if not v.replace('-', '').replace('_', '').isalnum():
            raise ValueError('Employee ID must contain only letters, numbers, hyphens, and underscores')
        return v.upper()

    @validator('username')
    def username_alphanumeric(cls, v):
        if not v.replace('-', '').replace('_', '').replace('.', '').isalnum():
            raise ValueError('Username must contain only letters, numbers, hyphens, underscores, and dots')
        return v.lower()


class EmployeeUpdate(BaseModel):
    # Basic Information
    first_name: Optional[str] = Field(None, min_length=1, max_length=50)
    last_name: Optional[str] = Field(None, min_length=1, max_length=50)
    email: Optional[EmailStr] = None
    phone: Optional[str] = Field(None, min_length=10, max_length=15)
    date_of_birth: Optional[date] = None
    gender: Optional[str] = Field(None, max_length=20)
    address: Optional[Address] = None

    # Employment Details
    employment_type: Optional[EmploymentType] = None
    position: Optional[str] = Field(None, min_length=1, max_length=100)
    department: Optional[str] = Field(None, min_length=1, max_length=100)
    manager_id: Optional[str] = None
    status: Optional[EmployeeStatus] = None

    # Store Assignment
    primary_store_id: Optional[str] = None
    additional_store_ids: Optional[List[str]] = None

    # System Access
    role: Optional[UserRole] = None
    permissions: Optional[List[str]] = None

    # Payroll Information
    payroll_info: Optional[PayrollInfo] = None

    # Schedule
    work_schedule: Optional[List[WorkSchedule]] = None
    shift_type: Optional[ShiftType] = None

    # Personal Information
    emergency_contacts: Optional[List[EmergencyContact]] = None
    notes: Optional[str] = Field(None, max_length=1000)


class EmployeeResponse(BaseModel):
    id: str
    user_id: str
    organization_id: str
    employee_id: str
    first_name: str
    last_name: str
    full_name: str
    email: str
    phone: str
    date_of_birth: Optional[date]
    gender: Optional[str]
    address: Optional[Address]

    # Employment Details
    hire_date: date
    employment_type: EmploymentType
    position: str
    department: str
    manager_id: Optional[str]
    manager_name: Optional[str]
    status: EmployeeStatus

    # Store Assignment
    primary_store_id: str
    primary_store_name: str
    additional_store_ids: List[str]
    additional_store_names: List[str]

    # System Access
    role: UserRole
    username: str
    permissions: List[str]
    is_active: bool

    # Payroll Information
    payroll_info: PayrollInfo

    # Schedule
    work_schedule: List[WorkSchedule]
    shift_type: ShiftType

    # Personal Information
    emergency_contacts: List[EmergencyContact]
    notes: Optional[str]

    # Metadata
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime]

    class Config:
        from_attributes = True


class EmployeeListResponse(BaseModel):
    employees: List[EmployeeResponse]
    total: int
    page: int
    per_page: int
    pages: int

    class Config:
        from_attributes = True


class EmployeeStats(BaseModel):
    employee_id: str
    employee_name: str
    total_sales: Decimal
    total_orders: int
    avg_order_value: Decimal
    performance_score: float
    attendance_rate: float
    hours_worked_this_month: float
    commission_earned: Decimal
    customer_satisfaction: float

    class Config:
        from_attributes = True


class EmployeePerformance(BaseModel):
    employee_id: str
    period_start: date
    period_end: date
    sales_target: Optional[Decimal] = None
    sales_achieved: Decimal = Decimal('0')
    orders_completed: int = 0
    customer_reviews: int = 0
    avg_customer_rating: float = 0.0
    attendance_days: int = 0
    total_working_days: int = 0
    goals_met: int = 0
    total_goals: int = 0
    manager_rating: Optional[float] = Field(None, ge=1, le=5)
    notes: Optional[str] = None

    class Config:
        from_attributes = True


class AttendanceRecord(BaseModel):
    employee_id: str
    date: date
    check_in: Optional[datetime] = None
    check_out: Optional[datetime] = None
    break_duration: int = 0  # minutes
    hours_worked: float = 0.0
    overtime_hours: float = 0.0
    status: str = "present"  # present, absent, late, early_leave, sick, vacation
    notes: Optional[str] = None

    class Config:
        from_attributes = True


class EmployeeScheduleUpdate(BaseModel):
    work_schedule: List[WorkSchedule]
    shift_type: ShiftType
    effective_date: date


class EmployeeRoleUpdate(BaseModel):
    role: UserRole
    permissions: List[str]
    reason: Optional[str] = None


class EmployeeStatusUpdate(BaseModel):
    status: EmployeeStatus
    effective_date: date
    reason: str = Field(..., min_length=1, max_length=500)
    notify_employee: bool = True


class EmployeeBulkAction(BaseModel):
    employee_ids: List[str]
    action: str  # activate, deactivate, transfer, update_role, etc.
    parameters: Dict[str, Any] = Field(default_factory=dict)


class EmployeePayrollUpdate(BaseModel):
    payroll_info: PayrollInfo
    effective_date: date
    reason: str = Field(..., min_length=1, max_length=500)


class EmployeeTransfer(BaseModel):
    employee_id: str
    new_primary_store_id: str
    new_additional_store_ids: List[str] = Field(default_factory=list)
    new_manager_id: Optional[str] = None
    transfer_date: date
    reason: str = Field(..., min_length=1, max_length=500)
    notify_employee: bool = True