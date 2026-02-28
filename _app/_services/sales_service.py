from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from decimal import Decimal
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId

from app._schemas.sale_schema import SaleCreate, SaleResponse, SaleList, SaleReturn, SalesReport, SaleItemResponse
from app._models.sale import Sale, SaleItem
from app.utils.exceptions import NotFoundError, ValidationError
from app.utils.helpers import serialize_datetime, calculate_pagination, generate_invoice_number


class SalesService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.sales_collection = db.sales
        self.products_collection = db.products
        self.inventory_collection = db.inventory
        self.customers_collection = db.customers
        self.stores_collection = db.stores
        self.users_collection = db.users

    async def create_sale(self, sale_data: SaleCreate, employee_id: str) -> SaleResponse:
        """Create a new sale"""
        # Generate invoice number
        invoice_number = generate_invoice_number(str(sale_data.store_id))
        
        # Calculate totals
        subtotal = Decimal('0')
        sale_items = []
        
        for item in sale_data.items:
            # Get product details
            product = await self.products_collection.find_one({"_id": ObjectId(item.product_id)})
            if not product:
                raise ValidationError(f"Product {item.product_id} not found")
            
            # Check inventory
            inventory = await self.inventory_collection.find_one({
                "product_id": ObjectId(item.product_id),
                "store_id": ObjectId(sale_data.store_id)
            })
            
            if not inventory or inventory["quantity"] < item.quantity:
                raise ValidationError(f"Insufficient inventory for product {product['name']}")
            
            # Calculate item total
            item_total = (item.quantity * item.unit_price) - item.discount
            subtotal += item_total
            
            sale_items.append({
                "product_id": ObjectId(item.product_id),
                "quantity": item.quantity,
                "unit_price": float(item.unit_price),
                "discount": float(item.discount),
                "total": float(item_total)
            })
        
        # Calculate tax and final total
        tax_amount = subtotal * sale_data.tax_rate
        total_amount = subtotal + tax_amount - sale_data.discount_amount
        
        # Create sale document (convert Decimals to float for MongoDB)
        sale_doc = {
            "invoice_number": invoice_number,
            "store_id": ObjectId(sale_data.store_id),
            "customer_id": ObjectId(sale_data.customer_id) if sale_data.customer_id else None,
            "employee_id": ObjectId(employee_id),
            "items": sale_items,
            "subtotal": float(subtotal),
            "tax_amount": float(tax_amount),
            "discount_amount": float(sale_data.discount_amount),
            "total_amount": float(total_amount),
            "payment_method": sale_data.payment_method.value,
            "payment_status": "paid",
            "sale_date": datetime.utcnow(),
            "notes": sale_data.notes
        }

        # Start transaction
        async with await self.db.client.start_session() as session:
            async with session.start_transaction():
                # Insert sale
                result = await self.sales_collection.insert_one(sale_doc, session=session)
                
                # Update inventory
                for item in sale_data.items:
                    await self.inventory_collection.update_one(
                        {
                            "product_id": ObjectId(item.product_id),
                            "store_id": ObjectId(sale_data.store_id)
                        },
                        {
                            "$inc": {"quantity": -item.quantity},
                            "$set": {"last_updated": datetime.utcnow()}
                        },
                        session=session
                    )
                
                # Update customer loyalty points if customer exists
                if sale_data.customer_id:
                    points_earned = int(total_amount / 10)  # 1 point per $10 spent
                    await self.customers_collection.update_one(
                        {"_id": ObjectId(sale_data.customer_id)},
                        {
                            "$inc": {"loyalty_points": points_earned},
                            "$set": {"last_purchase": datetime.utcnow()}
                        },
                        session=session
                    )
        
        # Return the created sale
        created_sale = await self.sales_collection.find_one({"_id": result.inserted_id})
        return await self._serialize_sale_with_details(created_sale)

    async def get_store_info(self, store_id: str) -> dict:
        """Get store information for invoice generation"""
        store = await self.stores_collection.find_one({"_id": ObjectId(store_id)})
        if not store:
            raise NotFoundError("Store not found")

        return {
            "name": store.get("name", "Store"),
            "address": store.get("address", {}),
            "phone": store.get("phone", ""),
            "email": store.get("email", "")
        }

    async def get_customer_info(self, customer_id: str) -> dict:
        """Get customer information for invoice generation"""
        customer = await self.customers_collection.find_one({"_id": ObjectId(customer_id)})
        if not customer:
            return None

        return {
            "name": customer.get("name", "Customer"),
            "address": customer.get("address", {}),
            "phone": customer.get("phone", ""),
            "email": customer.get("email", "")
        }

    async def get_sale(self, sale_id: str) -> SaleResponse:
        """Get sale by ID"""
        try:
            sale_doc = await self.sales_collection.find_one({"_id": ObjectId(sale_id)})
            if not sale_doc:
                raise NotFoundError("Sale not found")
            return await self._serialize_sale_with_details(sale_doc)
        except Exception as e:
            if isinstance(e, NotFoundError):
                raise e
            raise ValidationError("Invalid sale ID")

    async def list_sales(self, store_id: Optional[str] = None, page: int = 1, per_page: int = 20,
                        start_date: Optional[datetime] = None, end_date: Optional[datetime] = None) -> SaleList:
        """List sales with pagination and filters"""
        skip = (page - 1) * per_page
        query = {}
        
        if store_id:
            query["store_id"] = ObjectId(store_id)
        
        if start_date or end_date:
            date_query = {}
            if start_date:
                date_query["$gte"] = start_date
            if end_date:
                date_query["$lte"] = end_date
            query["sale_date"] = date_query

        total = await self.sales_collection.count_documents(query)
        
        # Calculate total amount for the filtered sales
        pipeline = [
            {"$match": query},
            {"$group": {"_id": None, "total_amount": {"$sum": "$total_amount"}}}
        ]
        total_amount_result = await self.sales_collection.aggregate(pipeline).to_list(length=1)
        total_amount = total_amount_result[0]["total_amount"] if total_amount_result else Decimal('0')
        
        sales_cursor = self.sales_collection.find(query).sort("sale_date", -1).skip(skip).limit(per_page)
        sales = await sales_cursor.to_list(length=per_page)

        serialized_sales = []
        for sale in sales:
            serialized_sales.append(await self._serialize_sale_with_details(sale))

        pagination = calculate_pagination(page, per_page, total)
        return SaleList(
            sales=serialized_sales,
            total_amount=total_amount,
            **pagination
        )

    async def process_return(self, return_data: SaleReturn, employee_id: str) -> SaleResponse:
        """Process a sale return"""
        # Get the original sale
        sale_doc = await self.sales_collection.find_one({"_id": ObjectId(return_data.sale_id)})
        if not sale_doc:
            raise NotFoundError("Original sale not found")

        # Start transaction for return
        async with await self.db.client.start_session() as session:
            async with session.start_transaction():
                # Update sale status
                await self.sales_collection.update_one(
                    {"_id": ObjectId(return_data.sale_id)},
                    {"$set": {"payment_status": "refunded"}},
                    session=session
                )
                
                # Restore inventory for returned items
                for item in return_data.items:
                    await self.inventory_collection.update_one(
                        {
                            "product_id": ObjectId(item["product_id"]),
                            "store_id": sale_doc["store_id"]
                        },
                        {
                            "$inc": {"quantity": item["quantity"]},
                            "$set": {"last_updated": datetime.utcnow()}
                        },
                        session=session
                    )
                
                # Create return record
                return_record = {
                    "sale_id": ObjectId(return_data.sale_id),
                    "items": return_data.items,
                    "reason": return_data.reason,
                    "refund_amount": return_data.refund_amount,
                    "employee_id": ObjectId(employee_id),
                    "return_date": datetime.utcnow()
                }
                await self.db.sale_returns.insert_one(return_record, session=session)

        updated_sale = await self.sales_collection.find_one({"_id": ObjectId(return_data.sale_id)})
        return await self._serialize_sale_with_details(updated_sale)

    async def get_sales_report(self, store_id: Optional[str] = None, 
                             start_date: Optional[datetime] = None,
                             end_date: Optional[datetime] = None) -> SalesReport:
        """Generate sales report"""
        # Set default date range (last 30 days)
        if not end_date:
            end_date = datetime.utcnow()
        if not start_date:
            start_date = end_date - timedelta(days=30)

        query = {"sale_date": {"$gte": start_date, "$lte": end_date}}
        if store_id:
            query["store_id"] = ObjectId(store_id)

        # Basic sales stats
        pipeline = [
            {"$match": query},
            {
                "$group": {
                    "_id": None,
                    "total_sales": {"$sum": 1},
                    "total_amount": {"$sum": "$total_amount"},
                    "average_sale_amount": {"$avg": "$total_amount"}
                }
            }
        ]
        
        stats_result = await self.sales_collection.aggregate(pipeline).to_list(length=1)
        stats = stats_result[0] if stats_result else {
            "total_sales": 0,
            "total_amount": Decimal('0'),
            "average_sale_amount": Decimal('0')
        }

        # Top products
        top_products_pipeline = [
            {"$match": query},
            {"$unwind": "$items"},
            {
                "$group": {
                    "_id": "$items.product_id",
                    "total_quantity": {"$sum": "$items.quantity"},
                    "total_revenue": {"$sum": "$items.total"}
                }
            },
            {"$sort": {"total_quantity": -1}},
            {"$limit": 10}
        ]
        
        top_products_result = await self.sales_collection.aggregate(top_products_pipeline).to_list(length=10)

        # Sales by payment method
        payment_method_pipeline = [
            {"$match": query},
            {
                "$group": {
                    "_id": "$payment_method",
                    "count": {"$sum": 1},
                    "total_amount": {"$sum": "$total_amount"}
                }
            }
        ]
        
        payment_methods_result = await self.sales_collection.aggregate(payment_method_pipeline).to_list(length=None)
        sales_by_payment_method = {
            result["_id"]: {
                "count": result["count"],
                "total_amount": float(result["total_amount"])
            } for result in payment_methods_result
        }

        return SalesReport(
            period_start=start_date.isoformat(),
            period_end=end_date.isoformat(),
            total_sales=stats["total_sales"],
            total_amount=stats["total_amount"],
            average_sale_amount=stats["average_sale_amount"],
            top_products=top_products_result,
            sales_by_payment_method=sales_by_payment_method
        )

    async def _serialize_sale_with_details(self, sale_doc: dict) -> SaleResponse:
        """Convert sale document to SaleResponse with related data"""
        # Get related data
        store = await self.stores_collection.find_one({"_id": sale_doc["store_id"]}) if sale_doc.get("store_id") else None
        customer = await self.customers_collection.find_one({"_id": sale_doc["customer_id"]}) if sale_doc.get("customer_id") else None
        employee = await self.users_collection.find_one({"_id": sale_doc["employee_id"]}) if sale_doc.get("employee_id") else None

        # Serialize items with product details
        items = []
        for item in sale_doc["items"]:
            product = await self.products_collection.find_one({"_id": item["product_id"]})
            items.append(SaleItemResponse(
                product_id=str(item["product_id"]),
                quantity=item["quantity"],
                unit_price=item["unit_price"],
                discount=item["discount"],
                total=item["total"],
                product_name=product["name"] if product else None,
                product_sku=product["sku"] if product else None
            ))

        return SaleResponse(
            id=str(sale_doc["_id"]),
            invoice_number=sale_doc["invoice_number"],
            store_id=str(sale_doc["store_id"]),
            customer_id=str(sale_doc["customer_id"]) if sale_doc.get("customer_id") else None,
            employee_id=str(sale_doc["employee_id"]),
            items=items,
            subtotal=sale_doc["subtotal"],
            tax_amount=sale_doc["tax_amount"],
            discount_amount=sale_doc["discount_amount"],
            total_amount=sale_doc["total_amount"],
            payment_method=sale_doc["payment_method"],
            payment_status=sale_doc["payment_status"],
            sale_date=serialize_datetime(sale_doc["sale_date"]),
            notes=sale_doc.get("notes"),
            store_name=store["name"] if store else None,
            customer_name=customer["name"] if customer else None,
            employee_name=employee["username"] if employee else None
        )