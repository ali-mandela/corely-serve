from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId

from app.utils.helpers import serialize_datetime


class ReportService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.sales_collection = db.sales
        self.products_collection = db.products
        self.inventory_collection = db.inventory
        self.customers_collection = db.customers
        self.employees_collection = db.employees
        self.stores_collection = db.stores

    async def get_dashboard_stats(self, store_id: Optional[str] = None) -> Dict[str, Any]:
        """Get dashboard statistics"""
        # Base query
        base_query = {}
        if store_id:
            base_query["store_id"] = ObjectId(store_id)

        # Today's sales
        today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        today_query = {**base_query, "sale_date": {"$gte": today_start}}
        
        today_sales_pipeline = [
            {"$match": today_query},
            {
                "$group": {
                    "_id": None,
                    "total_sales": {"$sum": 1},
                    "total_amount": {"$sum": "$total_amount"}
                }
            }
        ]
        
        today_result = await self.sales_collection.aggregate(today_sales_pipeline).to_list(length=1)
        today_stats = today_result[0] if today_result else {"total_sales": 0, "total_amount": 0}

        # This week's sales
        week_start = today_start - timedelta(days=today_start.weekday())
        week_query = {**base_query, "sale_date": {"$gte": week_start}}
        
        week_result = await self.sales_collection.aggregate([
            {"$match": week_query},
            {"$group": {"_id": None, "total_sales": {"$sum": 1}, "total_amount": {"$sum": "$total_amount"}}}
        ]).to_list(length=1)
        week_stats = week_result[0] if week_result else {"total_sales": 0, "total_amount": 0}

        # This month's sales
        month_start = today_start.replace(day=1)
        month_query = {**base_query, "sale_date": {"$gte": month_start}}
        
        month_result = await self.sales_collection.aggregate([
            {"$match": month_query},
            {"$group": {"_id": None, "total_sales": {"$sum": 1}, "total_amount": {"$sum": "$total_amount"}}}
        ]).to_list(length=1)
        month_stats = month_result[0] if month_result else {"total_sales": 0, "total_amount": 0}

        # Low stock count
        inventory_query = {"quantity": {"$lte": "$reorder_point"}}
        if store_id:
            inventory_query["store_id"] = ObjectId(store_id)
        
        low_stock_count = await self.inventory_collection.count_documents({
            **inventory_query,
            "$expr": {"$lte": ["$quantity", "$reorder_point"]}
        })

        # Out of stock count
        out_of_stock_query = {"quantity": 0}
        if store_id:
            out_of_stock_query["store_id"] = ObjectId(store_id)
        out_of_stock_count = await self.inventory_collection.count_documents(out_of_stock_query)

        # Total customers
        total_customers = await self.customers_collection.count_documents({})

        # Active employees
        active_employees_query = {"is_active": True}
        if store_id:
            active_employees_query["$or"] = [
                {"store_id": ObjectId(store_id)},
                {"additional_store_ids": ObjectId(store_id)}
            ]
        active_employees = await self.employees_collection.count_documents(active_employees_query)

        return {
            "today": {
                "sales_count": today_stats["total_sales"],
                "sales_amount": float(today_stats["total_amount"])
            },
            "this_week": {
                "sales_count": week_stats["total_sales"],
                "sales_amount": float(week_stats["total_amount"])
            },
            "this_month": {
                "sales_count": month_stats["total_sales"],
                "sales_amount": float(month_stats["total_amount"])
            },
            "inventory": {
                "low_stock_count": low_stock_count,
                "out_of_stock_count": out_of_stock_count
            },
            "customers": {
                "total_count": total_customers
            },
            "employees": {
                "active_count": active_employees
            }
        }

    async def get_sales_analytics(self, store_id: Optional[str] = None, 
                                days: int = 30) -> Dict[str, Any]:
        """Get sales analytics for the specified period"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        base_query = {"sale_date": {"$gte": start_date, "$lte": end_date}}
        if store_id:
            base_query["store_id"] = ObjectId(store_id)

        # Daily sales trend
        daily_sales_pipeline = [
            {"$match": base_query},
            {
                "$group": {
                    "_id": {
                        "$dateToString": {
                            "format": "%Y-%m-%d",
                            "date": "$sale_date"
                        }
                    },
                    "sales_count": {"$sum": 1},
                    "total_amount": {"$sum": "$total_amount"}
                }
            },
            {"$sort": {"_id": 1}}
        ]
        
        daily_sales = await self.sales_collection.aggregate(daily_sales_pipeline).to_list(length=None)

        # Top selling products
        top_products_pipeline = [
            {"$match": base_query},
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
        
        # Enrich with product details
        top_products = []
        for item in top_products_result:
            product = await self.products_collection.find_one({"_id": item["_id"]})
            top_products.append({
                "product_id": str(item["_id"]),
                "product_name": product["name"] if product else "Unknown",
                "product_sku": product["sku"] if product else "Unknown",
                "total_quantity": item["total_quantity"],
                "total_revenue": float(item["total_revenue"])
            })

        # Sales by payment method
        payment_method_pipeline = [
            {"$match": base_query},
            {
                "$group": {
                    "_id": "$payment_method",
                    "count": {"$sum": 1},
                    "total_amount": {"$sum": "$total_amount"}
                }
            }
        ]
        
        payment_methods = await self.sales_collection.aggregate(payment_method_pipeline).to_list(length=None)
        payment_method_stats = {
            method["_id"]: {
                "count": method["count"],
                "total_amount": float(method["total_amount"])
            } for method in payment_methods
        }

        # Hourly sales pattern
        hourly_sales_pipeline = [
            {"$match": base_query},
            {
                "$group": {
                    "_id": {"$hour": "$sale_date"},
                    "sales_count": {"$sum": 1},
                    "total_amount": {"$sum": "$total_amount"}
                }
            },
            {"$sort": {"_id": 1}}
        ]
        
        hourly_sales = await self.sales_collection.aggregate(hourly_sales_pipeline).to_list(length=None)

        return {
            "period": {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "days": days
            },
            "daily_sales": [
                {
                    "date": item["_id"],
                    "sales_count": item["sales_count"],
                    "total_amount": float(item["total_amount"])
                } for item in daily_sales
            ],
            "top_products": top_products,
            "payment_methods": payment_method_stats,
            "hourly_pattern": [
                {
                    "hour": item["_id"],
                    "sales_count": item["sales_count"],
                    "total_amount": float(item["total_amount"])
                } for item in hourly_sales
            ]
        }

    async def get_inventory_report(self, store_id: Optional[str] = None) -> Dict[str, Any]:
        """Get comprehensive inventory report"""
        base_query = {}
        if store_id:
            base_query["store_id"] = ObjectId(store_id)

        # Inventory summary
        inventory_pipeline = [
            {"$match": base_query},
            {
                "$group": {
                    "_id": None,
                    "total_products": {"$sum": 1},
                    "total_quantity": {"$sum": "$quantity"},
                    "total_reserved": {"$sum": "$reserved_quantity"},
                    "low_stock_items": {
                        "$sum": {
                            "$cond": [
                                {"$lte": ["$quantity", "$reorder_point"]},
                                1,
                                0
                            ]
                        }
                    },
                    "out_of_stock_items": {
                        "$sum": {
                            "$cond": [{"$eq": ["$quantity", 0]}, 1, 0]
                        }
                    }
                }
            }
        ]
        
        inventory_summary_result = await self.inventory_collection.aggregate(inventory_pipeline).to_list(length=1)
        inventory_summary = inventory_summary_result[0] if inventory_summary_result else {
            "total_products": 0,
            "total_quantity": 0,
            "total_reserved": 0,
            "low_stock_items": 0,
            "out_of_stock_items": 0
        }

        # Inventory by category
        category_pipeline = [
            {"$match": base_query},
            {
                "$lookup": {
                    "from": "products",
                    "localField": "product_id",
                    "foreignField": "_id",
                    "as": "product"
                }
            },
            {"$unwind": "$product"},
            {
                "$group": {
                    "_id": "$product.category",
                    "total_quantity": {"$sum": "$quantity"},
                    "product_count": {"$sum": 1},
                    "total_value": {
                        "$sum": {
                            "$multiply": ["$quantity", "$product.cost_price"]
                        }
                    }
                }
            },
            {"$sort": {"total_value": -1}}
        ]
        
        category_stats = await self.inventory_collection.aggregate(category_pipeline).to_list(length=None)

        # Top products by value
        value_pipeline = [
            {"$match": base_query},
            {
                "$lookup": {
                    "from": "products",
                    "localField": "product_id",
                    "foreignField": "_id",
                    "as": "product"
                }
            },
            {"$unwind": "$product"},
            {
                "$project": {
                    "product_id": "$product_id",
                    "product_name": "$product.name",
                    "product_sku": "$product.sku",
                    "quantity": 1,
                    "cost_price": "$product.cost_price",
                    "total_value": {
                        "$multiply": ["$quantity", "$product.cost_price"]
                    }
                }
            },
            {"$sort": {"total_value": -1}},
            {"$limit": 20}
        ]
        
        top_value_products = await self.inventory_collection.aggregate(value_pipeline).to_list(length=20)

        return {
            "summary": inventory_summary,
            "by_category": [
                {
                    "category": item["_id"],
                    "total_quantity": item["total_quantity"],
                    "product_count": item["product_count"],
                    "total_value": float(item["total_value"])
                } for item in category_stats
            ],
            "top_value_products": [
                {
                    "product_id": str(item["product_id"]),
                    "product_name": item["product_name"],
                    "product_sku": item["product_sku"],
                    "quantity": item["quantity"],
                    "cost_price": float(item["cost_price"]),
                    "total_value": float(item["total_value"])
                } for item in top_value_products
            ]
        }

    async def get_customer_analytics(self) -> Dict[str, Any]:
        """Get customer analytics"""
        # Customer summary
        total_customers = await self.customers_collection.count_documents({})
        retail_customers = await self.customers_collection.count_documents({"customer_type": "retail"})
        business_customers = await self.customers_collection.count_documents({"customer_type": "business"})

        # Top customers by purchases
        top_customers_pipeline = [
            {
                "$lookup": {
                    "from": "sales",
                    "localField": "_id",
                    "foreignField": "customer_id",
                    "as": "purchases"
                }
            },
            {
                "$project": {
                    "name": 1,
                    "customer_type": 1,
                    "loyalty_points": 1,
                    "purchase_count": {"$size": "$purchases"},
                    "total_spent": {"$sum": "$purchases.total_amount"}
                }
            },
            {"$sort": {"total_spent": -1}},
            {"$limit": 10}
        ]
        
        top_customers = await self.customers_collection.aggregate(top_customers_pipeline).to_list(length=10)

        # Customer registration trend (last 12 months)
        twelve_months_ago = datetime.now() - timedelta(days=365)
        registration_trend_pipeline = [
            {
                "$match": {
                    "registration_date": {"$gte": twelve_months_ago}
                }
            },
            {
                "$group": {
                    "_id": {
                        "$dateToString": {
                            "format": "%Y-%m",
                            "date": "$registration_date"
                        }
                    },
                    "new_customers": {"$sum": 1}
                }
            },
            {"$sort": {"_id": 1}}
        ]
        
        registration_trend = await self.customers_collection.aggregate(registration_trend_pipeline).to_list(length=None)

        return {
            "summary": {
                "total_customers": total_customers,
                "retail_customers": retail_customers,
                "business_customers": business_customers
            },
            "top_customers": [
                {
                    "customer_id": str(customer["_id"]),
                    "name": customer["name"],
                    "customer_type": customer["customer_type"],
                    "loyalty_points": customer["loyalty_points"],
                    "purchase_count": customer["purchase_count"],
                    "total_spent": float(customer["total_spent"])
                } for customer in top_customers
            ],
            "registration_trend": [
                {
                    "month": item["_id"],
                    "new_customers": item["new_customers"]
                } for item in registration_trend
            ]
        }

    async def get_multi_store_comparison(self) -> Dict[str, Any]:
        """Get comparison data across all stores"""
        # Get all active stores
        stores = await self.stores_collection.find({"is_active": True}).to_list(length=None)
        
        store_comparisons = []
        
        for store in stores:
            store_id = store["_id"]
            
            # Get today's sales for each store
            today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            today_sales_pipeline = [
                {
                    "$match": {
                        "store_id": store_id,
                        "sale_date": {"$gte": today_start}
                    }
                },
                {
                    "$group": {
                        "_id": None,
                        "sales_count": {"$sum": 1},
                        "sales_amount": {"$sum": "$total_amount"}
                    }
                }
            ]
            
            today_sales_result = await self.sales_collection.aggregate(today_sales_pipeline).to_list(length=1)
            today_sales = today_sales_result[0] if today_sales_result else {"sales_count": 0, "sales_amount": 0}
            
            # Get inventory count
            inventory_count = await self.inventory_collection.count_documents({"store_id": store_id})
            
            # Get employee count
            employee_count = await self.employees_collection.count_documents({
                "$or": [
                    {"store_id": store_id},
                    {"additional_store_ids": store_id}
                ],
                "is_active": True
            })
            
            store_comparisons.append({
                "store_id": str(store_id),
                "store_name": store["name"],
                "store_location": f"{store['address']['city']}, {store['address']['state']}",
                "today_sales_count": today_sales["sales_count"],
                "today_sales_amount": float(today_sales["sales_amount"]),
                "inventory_items": inventory_count,
                "employee_count": employee_count
            })
        
        # Sort by today's sales amount
        store_comparisons.sort(key=lambda x: x["today_sales_amount"], reverse=True)
        
        # Calculate totals
        total_sales_count = sum(store["today_sales_count"] for store in store_comparisons)
        total_sales_amount = sum(store["today_sales_amount"] for store in store_comparisons)
        total_inventory_items = sum(store["inventory_items"] for store in store_comparisons)
        total_employees = sum(store["employee_count"] for store in store_comparisons)
        
        return {
            "summary": {
                "total_stores": len(store_comparisons),
                "total_sales_today": total_sales_count,
                "total_revenue_today": total_sales_amount,
                "total_inventory_items": total_inventory_items,
                "total_employees": total_employees
            },
            "store_comparisons": store_comparisons,
            "best_performing_store": store_comparisons[0] if store_comparisons else None
        }

    async def get_store_performance_report(self, days: int = 30) -> Dict[str, Any]:
        """Get performance report for all stores"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Get all active stores
        stores = await self.stores_collection.find({"is_active": True}).to_list(length=None)
        
        performance_data = []
        
        for store in stores:
            store_id = store["_id"]
            
            # Sales performance
            sales_pipeline = [
                {
                    "$match": {
                        "store_id": store_id,
                        "sale_date": {"$gte": start_date, "$lte": end_date}
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
            
            sales_result = await self.sales_collection.aggregate(sales_pipeline).to_list(length=1)
            sales_stats = sales_result[0] if sales_result else {
                "total_sales": 0,
                "total_revenue": 0,
                "average_sale_amount": 0
            }
            
            # Inventory turnover (simplified calculation)
            inventory_count = await self.inventory_collection.count_documents({"store_id": store_id})
            
            # Low stock percentage
            low_stock_count = await self.inventory_collection.count_documents({
                "store_id": store_id,
                "$expr": {"$lte": ["$quantity", "$reorder_point"]}
            })
            
            low_stock_percentage = (low_stock_count / inventory_count * 100) if inventory_count > 0 else 0
            
            performance_data.append({
                "store_id": str(store_id),
                "store_name": store["name"],
                "location": f"{store['address']['city']}, {store['address']['state']}",
                "total_sales": sales_stats["total_sales"],
                "total_revenue": float(sales_stats["total_revenue"]),
                "average_sale_amount": float(sales_stats["average_sale_amount"]),
                "inventory_items": inventory_count,
                "low_stock_percentage": round(low_stock_percentage, 2),
                "revenue_per_day": round(float(sales_stats["total_revenue"]) / days, 2)
            })
        
        # Sort by total revenue
        performance_data.sort(key=lambda x: x["total_revenue"], reverse=True)
        
        return {
            "period": {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "days": days
            },
            "store_performance": performance_data,
            "summary": {
                "total_stores": len(performance_data),
                "total_revenue": sum(store["total_revenue"] for store in performance_data),
                "total_sales": sum(store["total_sales"] for store in performance_data),
                "average_revenue_per_store": sum(store["total_revenue"] for store in performance_data) / len(performance_data) if performance_data else 0
            }
        }