from typing import Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from fastapi.responses import StreamingResponse
from motor.motor_asyncio import AsyncIOMotorDatabase
import io

from app._core.database import get_database
from app._services.sales_service import SalesService
from app._services.invoice_service import InvoiceService
from app._schemas.sale_schema import SaleCreate, SaleResponse, SaleList, SaleReturn, SalesReport
from app._schemas.user_schema import UserResponse
from app._services.auth_service import get_current_user
from app.utils.exceptions import NotFoundError, ValidationError
from app._models.user import UserRole

# Enterprise security imports
from app._core.abac.decorators import require_permission, require_read_permission, require_write_permission
from app._core.tenant_isolation import get_tenant_context, TenantContext, require_tenant_isolation
from app._core.audit.logger import log_data_event

router = APIRouter()


def require_sales_access_permission(current_user: UserResponse = Depends(get_current_user)):
    """Dependency to ensure user can access sales data"""
    if current_user.role not in [UserRole.ADMIN, UserRole.MANAGER]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Permission denied: Cannot access sales data"
        )
    return current_user


def require_sales_management_permission(current_user: UserResponse = Depends(get_current_user)):
    """Dependency to ensure user can manage sales"""
    if current_user.role not in [UserRole.ADMIN, UserRole.MANAGER]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Permission denied: Cannot manage sales"
        )
    return current_user


async def get_sales_service(db: AsyncIOMotorDatabase = Depends(get_database)) -> SalesService:
    return SalesService(db)


@router.post("/", response_model=SaleResponse, status_code=status.HTTP_201_CREATED)
@require_permission("sale", "create")
@require_tenant_isolation()
async def create_sale(
    sale_data: SaleCreate,
    request: Request = None,
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    sales_service: SalesService = Depends(get_sales_service)
):
    """Create a new sale"""
    try:
        sale = await sales_service.create_sale(sale_data, str(current_user.id))

        # Log data creation
        await log_data_event(
            user_id=current_user.id,
            operation="create",
            resource_type="sale",
            resource_id=str(sale.id),
            success=True,
            tenant_id=tenant_context.tenant_id
        )

        return sale
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))


@router.get("/", response_model=SaleList)
@require_read_permission("sale")
@require_tenant_isolation()
async def list_sales(
    store_id: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    request: Request = None,
    current_user: UserResponse = Depends(get_current_user),
    tenant_context: TenantContext = Depends(get_tenant_context),
    sales_service: SalesService = Depends(get_sales_service)
):
    """List sales with pagination and filters"""
    sales_list = await sales_service.list_sales(
        store_id=store_id,
        page=page,
        per_page=per_page,
        start_date=start_date,
        end_date=end_date,
        tenant_id=tenant_context.tenant_id
    )

    # Log data access
    await log_data_event(
        user_id=current_user.id,
        operation="read",
        resource_type="sale",
        success=True,
        tenant_id=tenant_context.tenant_id,
        data_count=len(sales_list.sales) if sales_list.sales else 0
    )

    return sales_list


@router.get("/{sale_id}", response_model=SaleResponse)
async def get_sale(
    sale_id: str,
    current_user: UserResponse = Depends(require_sales_access_permission),
    sales_service: SalesService = Depends(get_sales_service)
):
    """Get sale by ID"""
    try:
        return await sales_service.get_sale(sale_id)
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))


@router.post("/return", response_model=SaleResponse)
async def process_return(
    return_data: SaleReturn,
    current_user: UserResponse = Depends(require_sales_management_permission),
    sales_service: SalesService = Depends(get_sales_service)
):
    """Process a sale return"""
    try:
        return await sales_service.process_return(return_data, str(current_user.id))
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))


@router.get("/reports/summary", response_model=SalesReport)
async def get_sales_report(
    store_id: Optional[str] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    current_user: UserResponse = Depends(require_sales_access_permission),
    sales_service: SalesService = Depends(get_sales_service)
):
    """Get sales report"""
    return await sales_service.get_sales_report(
        store_id=store_id,
        start_date=start_date,
        end_date=end_date
    )


@router.get("/{sale_id}/invoice")
async def download_invoice(
    sale_id: str,
    current_user: UserResponse = Depends(require_sales_access_permission),
    sales_service: SalesService = Depends(get_sales_service)
):
    """Download professional PDF invoice"""
    try:
        # Get sale details
        sale = await sales_service.get_sale(sale_id)

        # Get store and customer details
        store_info = await sales_service.get_store_info(str(sale.store_id))
        customer_info = None
        if sale.customer_id:
            customer_info = await sales_service.get_customer_info(str(sale.customer_id))

        # Company info (this should come from organization settings)
        company_info = {
            "name": "Your Company Name",
            "address": "123 Business Street",
            "city": "Business City",
            "state": "ST",
            "zip_code": "12345",
            "phone": "+1 (555) 123-4567",
            "email": "info@yourcompany.com"
        }

        # Generate PDF
        invoice_service = InvoiceService()
        pdf_bytes = await invoice_service.generate_invoice_pdf(
            sale=sale,
            company_info=company_info,
            store_info=store_info,
            customer_info=customer_info
        )

        # Return PDF as download
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=invoice_{sale.invoice_number}.pdf"
            }
        )
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/{sale_id}/receipt")
async def download_receipt(
    sale_id: str,
    current_user: UserResponse = Depends(require_sales_access_permission),
    sales_service: SalesService = Depends(get_sales_service)
):
    """Download simple receipt PDF"""
    try:
        # Get sale details
        sale = await sales_service.get_sale(sale_id)

        # Get store details
        store_info = await sales_service.get_store_info(str(sale.store_id))
        customer_info = None
        if sale.customer_id:
            customer_info = await sales_service.get_customer_info(str(sale.customer_id))

        # Generate receipt PDF
        invoice_service = InvoiceService()
        pdf_bytes = invoice_service.generate_receipt_pdf(
            sale=sale,
            store_info=store_info,
            customer_info=customer_info
        )

        # Return PDF as download
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=receipt_{sale.invoice_number}.pdf"
            }
        )
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/{sale_id}/print")
async def print_receipt(
    sale_id: str,
    format: str = Query("receipt", enum=["receipt", "invoice"]),
    current_user: UserResponse = Depends(require_sales_access_permission),
    sales_service: SalesService = Depends(get_sales_service)
):
    """Get receipt/invoice for printing (returns PDF for browser display)"""
    try:
        # Get sale details
        sale = await sales_service.get_sale(sale_id)

        # Get store details
        store_info = await sales_service.get_store_info(str(sale.store_id))
        customer_info = None
        if sale.customer_id:
            customer_info = await sales_service.get_customer_info(str(sale.customer_id))

        invoice_service = InvoiceService()

        if format == "invoice":
            # Company info (this should come from organization settings)
            company_info = {
                "name": "Your Company Name",
                "address": "123 Business Street",
                "city": "Business City",
                "state": "ST",
                "zip_code": "12345",
                "phone": "+1 (555) 123-4567",
                "email": "info@yourcompany.com"
            }
            pdf_bytes = await invoice_service.generate_invoice_pdf(
                sale=sale,
                company_info=company_info,
                store_info=store_info,
                customer_info=customer_info
            )
        else:
            pdf_bytes = invoice_service.generate_receipt_pdf(
                sale=sale,
                store_info=store_info,
                customer_info=customer_info
            )

        # Return PDF for browser display (no download)
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf"
        )
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))