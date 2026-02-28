from typing import Optional
from fastapi import APIRouter, Depends, Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from app._core.database import get_database
from app._services.report_service import ReportService
from app._schemas.user_schema import UserResponse
from app._services.auth_service import get_current_user

router = APIRouter()


async def get_report_service(db: AsyncIOMotorDatabase = Depends(get_database)) -> ReportService:
    return ReportService(db)


@router.get("/dashboard")
async def get_dashboard_stats(
    store_id: Optional[str] = Query(None),
    current_user: UserResponse = Depends(get_current_user),
    report_service: ReportService = Depends(get_report_service)
):
    """Get dashboard statistics"""
    return await report_service.get_dashboard_stats(store_id)


@router.get("/sales-analytics")
async def get_sales_analytics(
    store_id: Optional[str] = Query(None),
    days: int = Query(30, ge=1, le=365),
    current_user: UserResponse = Depends(get_current_user),
    report_service: ReportService = Depends(get_report_service)
):
    """Get sales analytics for the specified period"""
    return await report_service.get_sales_analytics(store_id, days)


@router.get("/inventory-report")
async def get_inventory_report(
    store_id: Optional[str] = Query(None),
    current_user: UserResponse = Depends(get_current_user),
    report_service: ReportService = Depends(get_report_service)
):
    """Get comprehensive inventory report"""
    return await report_service.get_inventory_report(store_id)


@router.get("/customer-analytics")
async def get_customer_analytics(
    current_user: UserResponse = Depends(get_current_user),
    report_service: ReportService = Depends(get_report_service)
):
    """Get customer analytics"""
    return await report_service.get_customer_analytics()


@router.get("/export/sales")
async def export_sales_report(
    store_id: Optional[str] = Query(None),
    days: int = Query(30, ge=1, le=365),
    format: str = Query("json", regex="^(json|csv|excel)$"),
    current_user: UserResponse = Depends(get_current_user),
    report_service: ReportService = Depends(get_report_service)
):
    """Export sales report in various formats"""
    # Get the data
    analytics_data = await report_service.get_sales_analytics(store_id, days)
    
    # In a real application, you would implement different export formats
    if format == "json":
        return analytics_data
    elif format == "csv":
        return {
            "message": "CSV export not implemented",
            "data": analytics_data,
            "format": "csv"
        }
    elif format == "excel":
        return {
            "message": "Excel export not implemented", 
            "data": analytics_data,
            "format": "excel"
        }


@router.get("/export/inventory")
async def export_inventory_report(
    store_id: Optional[str] = Query(None),
    format: str = Query("json", regex="^(json|csv|excel)$"),
    current_user: UserResponse = Depends(get_current_user),
    report_service: ReportService = Depends(get_report_service)
):
    """Export inventory report in various formats"""
    # Get the data
    inventory_data = await report_service.get_inventory_report(store_id)
    
    # In a real application, you would implement different export formats
    if format == "json":
        return inventory_data
    elif format == "csv":
        return {
            "message": "CSV export not implemented",
            "data": inventory_data,
            "format": "csv"
        }
    elif format == "excel":
        return {
            "message": "Excel export not implemented",
            "data": inventory_data,
            "format": "excel"
        }


@router.get("/multi-store-comparison")
async def get_multi_store_comparison(
    current_user: UserResponse = Depends(get_current_user),
    report_service: ReportService = Depends(get_report_service)
):
    """Get comparison data across all stores"""
    return await report_service.get_multi_store_comparison()


@router.get("/store-performance")
async def get_store_performance_report(
    days: int = Query(30, ge=1, le=365),
    current_user: UserResponse = Depends(get_current_user),
    report_service: ReportService = Depends(get_report_service)
):
    """Get performance report for all stores"""
    return await report_service.get_store_performance_report(days)