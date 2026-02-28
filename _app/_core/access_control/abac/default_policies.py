"""
Corely - Enterprise Multi-Tenant Retail Chain Management System
Production-Optimized Default ABAC Policies

This module provides comprehensive default ABAC policies specifically designed
for Corely's multi-tenant retail chain operations, integrating with the new
authentication system and role hierarchy.

Features:
- Complete 13-role hierarchy support (CUSTOMER to SUPER_ADMIN)
- Module-specific access controls for all organizational modules
- Store and warehouse hierarchical access
- Time-based access restrictions
- Multi-factor authentication requirements
- Retail-specific resource types and actions
- Performance-optimized policy structure
"""

from datetime import datetime, timezone
from typing import List, Dict, Any

from .policy_engine import Policy, PolicyRule, PolicyCondition, AttributeType, Effect, ConditionOperator
from app._core.auth.tokens import ROLE_HIERARCHY
from app._core.auth.sessions import ORGANIZATION_MODULES


def get_default_policies() -> List[Policy]:
    """Get comprehensive default ABAC policies for Corely retail system"""
    policies = []
    
    # Add all policy categories
    policies.extend(_get_system_admin_policies())
    policies.extend(_get_tenant_admin_policies())
    policies.extend(_get_store_management_policies())
    policies.extend(_get_warehouse_management_policies())
    policies.extend(_get_employee_management_policies())
    policies.extend(_get_inventory_module_policies())
    policies.extend(_get_pos_module_policies())
    policies.extend(_get_customer_management_policies())
    policies.extend(_get_analytics_module_policies())
    policies.extend(_get_accounting_module_policies())
    policies.extend(_get_hr_module_policies())
    policies.extend(_get_supply_chain_policies())
    policies.extend(_get_security_policies())
    policies.extend(_get_temporal_policies())
    policies.extend(_get_self_service_policies())
    
    return policies


def _get_system_admin_policies() -> List[Policy]:
    """Global system administrator policies"""
    policies = []
    
    # Super Admin Global Access
    super_admin_policy = Policy(
        policy_id="super_admin_global_policy",
        name="Super Administrator Global Access",
        description="SUPER_ADMIN role has unrestricted access to all system operations",
        version="2.0",
        tenant_id=None,
        rules=[
            PolicyRule(
                rule_id="super_admin_full_access",
                description="Super admins can perform any action on any resource",
                effect=Effect.PERMIT,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role",
                        operator=ConditionOperator.EQ,
                        value="SUPER_ADMIN"
                    )
                ],
                priority=1  # Highest priority
            )
        ]
    )
    policies.append(super_admin_policy)
    
    return policies


def _get_tenant_admin_policies() -> List[Policy]:
    """Tenant administrator policies"""
    policies = []
    
    # Tenant Admin Management Access
    tenant_admin_policy = Policy(
        policy_id="tenant_admin_policy",
        name="Tenant Administrator Access",
        description="TENANT_ADMIN can manage all resources within their tenant",
        version="2.0",
        tenant_id=None,
        rules=[
            PolicyRule(
                rule_id="tenant_admin_management_access",
                description="Tenant admins can manage all tenant resources",
                effect=Effect.PERMIT,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role",
                        operator=ConditionOperator.EQ,
                        value="TENANT_ADMIN"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.ACTION,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["read", "write", "create", "update", "delete", "admin"]
                    )
                ],
                priority=5
            ),
            PolicyRule(
                rule_id="tenant_admin_user_management",
                description="Tenant admins can manage all users in their tenant",
                effect=Effect.PERMIT,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role",
                        operator=ConditionOperator.EQ,
                        value="TENANT_ADMIN"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.EQ,
                        value="user"
                    )
                ],
                priority=5
            )
        ]
    )
    policies.append(tenant_admin_policy)
    
    # Tenant Manager Limited Access
    tenant_manager_policy = Policy(
        policy_id="tenant_manager_policy",
        name="Tenant Manager Access",
        description="TENANT_MANAGER can manage operations but not system settings",
        version="2.0",
        tenant_id=None,
        rules=[
            PolicyRule(
                rule_id="tenant_manager_operations_access",
                description="Tenant managers can manage operational resources",
                effect=Effect.PERMIT,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role",
                        operator=ConditionOperator.EQ,
                        value="TENANT_MANAGER"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["product", "inventory", "sale", "customer", "order", "shipment", "report"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.ACTION,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["read", "write", "create", "update"]
                    )
                ],
                priority=10
            ),
            PolicyRule(
                rule_id="tenant_manager_no_system_settings",
                description="Tenant managers cannot modify system settings",
                effect=Effect.DENY,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role",
                        operator=ConditionOperator.EQ,
                        value="TENANT_MANAGER"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["system_setting", "tenant_setting", "user", "role"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.ACTION,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["create", "update", "delete", "admin"]
                    )
                ],
                priority=8
            )
        ]
    )
    policies.append(tenant_manager_policy)
    
    return policies


def _get_store_management_policies() -> List[Policy]:
    """Store management policies for different management levels"""
    policies = []
    
    # Store Manager Access
    store_manager_policy = Policy(
        policy_id="store_manager_policy",
        name="Store Manager Access Control",
        description="STORE_MANAGER can manage their assigned store and its operations",
        version="2.0",
        tenant_id=None,
        rules=[
            PolicyRule(
                rule_id="store_manager_store_access",
                description="Store managers can manage their assigned stores",
                effect=Effect.PERMIT,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role",
                        operator=ConditionOperator.EQ,
                        value="STORE_MANAGER"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["store", "product", "inventory", "sale", "customer", "employee_schedule"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="store_id",
                        operator=ConditionOperator.STORE_HIERARCHY,
                        value="resource.store_id"
                    )
                ],
                priority=15
            ),
            PolicyRule(
                rule_id="store_manager_employee_management",
                description="Store managers can manage store employees",
                effect=Effect.PERMIT,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role",
                        operator=ConditionOperator.EQ,
                        value="STORE_MANAGER"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.EQ,
                        value="user"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="target_role",
                        operator=ConditionOperator.IN,
                        value=["CASHIER", "SALES_ASSOCIATE", "CUSTOMER_SERVICE_REP"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.ACTION,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["read", "update"]
                    )
                ],
                priority=15
            )
        ]
    )
    policies.append(store_manager_policy)
    
    # Assistant Manager Access
    assistant_manager_policy = Policy(
        policy_id="assistant_manager_policy",
        name="Assistant Manager Access Control",
        description="ASSISTANT_MANAGER has limited store management capabilities",
        version="2.0",
        tenant_id=None,
        rules=[
            PolicyRule(
                rule_id="assistant_manager_operations",
                description="Assistant managers can handle daily operations",
                effect=Effect.PERMIT,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role",
                        operator=ConditionOperator.EQ,
                        value="ASSISTANT_MANAGER"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["sale", "inventory", "customer", "product"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.ACTION,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["read", "write", "update"]
                    )
                ],
                priority=20
            ),
            PolicyRule(
                rule_id="assistant_manager_no_admin",
                description="Assistant managers cannot perform admin functions",
                effect=Effect.DENY,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role",
                        operator=ConditionOperator.EQ,
                        value="ASSISTANT_MANAGER"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.ACTION,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["admin", "delete", "create"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["user", "store", "system_setting"]
                    )
                ],
                priority=18
            )
        ]
    )
    policies.append(assistant_manager_policy)
    
    return policies


def _get_warehouse_management_policies() -> List[Policy]:
    """Warehouse management policies"""
    policies = []
    
    # Warehouse Manager Access
    warehouse_manager_policy = Policy(
        policy_id="warehouse_manager_policy",
        name="Warehouse Manager Access Control",
        description="WAREHOUSE_MANAGER can manage warehouse operations",
        version="2.0",
        tenant_id=None,
        rules=[
            PolicyRule(
                rule_id="warehouse_manager_full_access",
                description="Warehouse managers can manage all warehouse operations",
                effect=Effect.PERMIT,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role",
                        operator=ConditionOperator.EQ,
                        value="WAREHOUSE_MANAGER"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["warehouse", "inventory", "shipment", "receiving", "product", "supplier"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="warehouse_id",
                        operator=ConditionOperator.EQ,
                        value="resource.warehouse_id",
                        metadata={"allow_hierarchical": True}
                    )
                ],
                priority=15
            )
        ]
    )
    policies.append(warehouse_manager_policy)
    
    # Warehouse Supervisor Access
    warehouse_supervisor_policy = Policy(
        policy_id="warehouse_supervisor_policy",
        name="Warehouse Supervisor Access Control",
        description="WAREHOUSE_SUPERVISOR can supervise warehouse operations",
        version="2.0",
        tenant_id=None,
        rules=[
            PolicyRule(
                rule_id="warehouse_supervisor_operations",
                description="Warehouse supervisors can manage operational tasks",
                effect=Effect.PERMIT,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role",
                        operator=ConditionOperator.EQ,
                        value="WAREHOUSE_SUPERVISOR"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["inventory", "shipment", "receiving", "picking", "packing"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.ACTION,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["read", "write", "update", "execute"]
                    )
                ],
                priority=20
            )
        ]
    )
    policies.append(warehouse_supervisor_policy)
    
    # Warehouse Operator Access
    warehouse_operator_policy = Policy(
        policy_id="warehouse_operator_policy",
        name="Warehouse Operator Access Control",
        description="WAREHOUSE_OPERATOR can perform basic warehouse operations",
        version="2.0",
        tenant_id=None,
        rules=[
            PolicyRule(
                rule_id="warehouse_operator_basic_access",
                description="Warehouse operators can perform basic tasks",
                effect=Effect.PERMIT,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role",
                        operator=ConditionOperator.EQ,
                        value="WAREHOUSE_OPERATOR"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["inventory", "product", "picking_list", "packing_slip"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.ACTION,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["read", "update"]
                    )
                ],
                priority=25
            )
        ]
    )
    policies.append(warehouse_operator_policy)
    
    return policies


def _get_employee_management_policies() -> List[Policy]:
    """Employee management and supervision policies"""
    policies = []
    
    # Shift Supervisor Access
    shift_supervisor_policy = Policy(
        policy_id="shift_supervisor_policy",
        name="Shift Supervisor Access Control",
        description="SHIFT_SUPERVISOR can supervise shift operations",
        version="2.0",
        tenant_id=None,
        rules=[
            PolicyRule(
                rule_id="shift_supervisor_operations",
                description="Shift supervisors can manage shift operations",
                effect=Effect.PERMIT,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role",
                        operator=ConditionOperator.EQ,
                        value="SHIFT_SUPERVISOR"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["sale", "customer", "inventory", "pos_session", "cash_drawer"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.ACTION,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["read", "write", "update", "approve"]
                    )
                ],
                priority=20
            ),
            PolicyRule(
                rule_id="shift_supervisor_employee_oversight",
                description="Shift supervisors can oversee cashiers and associates",
                effect=Effect.PERMIT,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role",
                        operator=ConditionOperator.EQ,
                        value="SHIFT_SUPERVISOR"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.EQ,
                        value="user"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="target_role",
                        operator=ConditionOperator.IN,
                        value=["CASHIER", "SALES_ASSOCIATE"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.ACTION,
                        attribute_name="type",
                        operator=ConditionOperator.EQ,
                        value="read"
                    )
                ],
                priority=20
            )
        ]
    )
    policies.append(shift_supervisor_policy)
    
    return policies


def _get_inventory_module_policies() -> List[Policy]:
    """Inventory module specific policies"""
    policies = []
    
    # Inventory Clerk Access
    inventory_clerk_policy = Policy(
        policy_id="inventory_clerk_policy",
        name="Inventory Clerk Access Control",
        description="INVENTORY_CLERK can manage inventory operations",
        version="2.0",
        tenant_id=None,
        rules=[
            PolicyRule(
                rule_id="inventory_clerk_inventory_access",
                description="Inventory clerks can manage inventory data",
                effect=Effect.PERMIT,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role",
                        operator=ConditionOperator.EQ,
                        value="INVENTORY_CLERK"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["inventory", "product", "stock_count", "adjustment", "category"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.ACTION,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["read", "write", "update", "create"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="enabled_modules",
                        operator=ConditionOperator.CONTAINS,
                        value="inventory"
                    )
                ],
                priority=25
            )
        ]
    )
    policies.append(inventory_clerk_policy)
    
    # Inventory Module Access Control
    inventory_module_policy = Policy(
        policy_id="inventory_module_access_policy",
        name="Inventory Module Access Control",
        description="Control access to inventory module resources",
        version="2.0",
        tenant_id=None,
        rules=[
            PolicyRule(
                rule_id="inventory_module_enabled_check",
                description="Only allow access if inventory module is enabled",
                effect=Effect.DENY,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="module",
                        operator=ConditionOperator.EQ,
                        value="inventory"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="enabled_modules",
                        operator=ConditionOperator.NOT_CONTAINS,
                        value="inventory"
                    )
                ],
                priority=5
            )
        ]
    )
    policies.append(inventory_module_policy)
    
    return policies


def _get_pos_module_policies() -> List[Policy]:
    """Point of Sale module policies"""
    policies = []
    
    # Cashier Access
    cashier_policy = Policy(
        policy_id="cashier_policy",
        name="Cashier Access Control",
        description="CASHIER can process sales transactions",
        version="2.0",
        tenant_id=None,
        rules=[
            PolicyRule(
                rule_id="cashier_pos_access",
                description="Cashiers can process sales and manage cash drawer",
                effect=Effect.PERMIT,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role",
                        operator=ConditionOperator.EQ,
                        value="CASHIER"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["sale", "payment", "receipt", "cash_drawer", "return", "exchange"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.ACTION,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["read", "write", "create", "execute"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="enabled_modules",
                        operator=ConditionOperator.CONTAINS,
                        value="pos"
                    )
                ],
                priority=25
            ),
            PolicyRule(
                rule_id="cashier_customer_basic_access",
                description="Cashiers can access basic customer information",
                effect=Effect.PERMIT,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role",
                        operator=ConditionOperator.EQ,
                        value="CASHIER"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.EQ,
                        value="customer"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.ACTION,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["read", "update"]
                    )
                ],
                priority=25
            )
        ]
    )
    policies.append(cashier_policy)
    
    # Sales Associate Access
    sales_associate_policy = Policy(
        policy_id="sales_associate_policy",
        name="Sales Associate Access Control",
        description="SALES_ASSOCIATE can assist customers and process basic sales",
        version="2.0",
        tenant_id=None,
        rules=[
            PolicyRule(
                rule_id="sales_associate_customer_service",
                description="Sales associates can assist customers",
                effect=Effect.PERMIT,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role",
                        operator=ConditionOperator.EQ,
                        value="SALES_ASSOCIATE"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["customer", "product", "inventory", "sale"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.ACTION,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["read", "write", "create"]
                    )
                ],
                priority=25
            )
        ]
    )
    policies.append(sales_associate_policy)
    
    return policies


def _get_customer_management_policies() -> List[Policy]:
    """Customer service and management policies"""
    policies = []
    
    # Customer Service Manager Access
    cs_manager_policy = Policy(
        policy_id="customer_service_manager_policy",
        name="Customer Service Manager Access Control",
        description="CUSTOMER_SERVICE_MANAGER can manage customer service operations",
        version="2.0",
        tenant_id=None,
        rules=[
            PolicyRule(
                rule_id="cs_manager_full_customer_access",
                description="Customer service managers can manage all customer operations",
                effect=Effect.PERMIT,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role",
                        operator=ConditionOperator.EQ,
                        value="CUSTOMER_SERVICE_MANAGER"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["customer", "return", "exchange", "complaint", "loyalty", "communication"]
                    )
                ],
                priority=20
            )
        ]
    )
    policies.append(cs_manager_policy)
    
    # Customer Service Representative Access
    cs_rep_policy = Policy(
        policy_id="customer_service_rep_policy",
        name="Customer Service Representative Access Control", 
        description="CUSTOMER_SERVICE_REP can handle customer inquiries and basic operations",
        version="2.0",
        tenant_id=None,
        rules=[
            PolicyRule(
                rule_id="cs_rep_customer_support",
                description="Customer service reps can provide customer support",
                effect=Effect.PERMIT,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role",
                        operator=ConditionOperator.EQ,
                        value="CUSTOMER_SERVICE_REP"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["customer", "return", "exchange", "loyalty"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.ACTION,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["read", "write", "update"]
                    )
                ],
                priority=25
            )
        ]
    )
    policies.append(cs_rep_policy)
    
    return policies


def _get_analytics_module_policies() -> List[Policy]:
    """Analytics and business intelligence policies"""
    policies = []
    
    # Business Analyst Access
    business_analyst_policy = Policy(
        policy_id="business_analyst_policy",
        name="Business Analyst Access Control",
        description="BUSINESS_ANALYST can access analytics and reporting",
        version="2.0",
        tenant_id=None,
        rules=[
            PolicyRule(
                rule_id="business_analyst_analytics_access",
                description="Business analysts can access analytics and reports",
                effect=Effect.PERMIT,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role",
                        operator=ConditionOperator.EQ,
                        value="BUSINESS_ANALYST"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["report", "analytics", "dashboard", "metric", "kpi"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.ACTION,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["read", "create", "export"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="enabled_modules",
                        operator=ConditionOperator.CONTAINS,
                        value="analytics"
                    )
                ],
                priority=25
            )
        ]
    )
    policies.append(business_analyst_policy)
    
    # Financial Analyst Access
    financial_analyst_policy = Policy(
        policy_id="financial_analyst_policy",
        name="Financial Analyst Access Control",
        description="FINANCIAL_ANALYST can access financial analytics and reports",
        version="2.0",
        tenant_id=None,
        rules=[
            PolicyRule(
                rule_id="financial_analyst_financial_access",
                description="Financial analysts can access financial data and reports",
                effect=Effect.PERMIT,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role",
                        operator=ConditionOperator.EQ,
                        value="FINANCIAL_ANALYST"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["financial_report", "revenue", "profit", "cost", "budget", "forecast"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.ACTION,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["read", "create", "export", "analyze"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="enabled_modules",
                        operator=ConditionOperator.CONTAINS,
                        value="accounting"
                    )
                ],
                priority=25
            )
        ]
    )
    policies.append(financial_analyst_policy)
    
    return policies


def _get_accounting_module_policies() -> List[Policy]:
    """Accounting module access policies"""
    policies = []
    
    # Accounting Module Access Control
    accounting_module_policy = Policy(
        policy_id="accounting_module_access_policy",
        name="Accounting Module Access Control",
        description="Control access to financial and accounting resources",
        version="2.0",
        tenant_id=None,
        rules=[
            PolicyRule(
                rule_id="accounting_module_enabled_check",
                description="Deny access if accounting module not enabled",
                effect=Effect.DENY,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="module",
                        operator=ConditionOperator.EQ,
                        value="accounting"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="enabled_modules",
                        operator=ConditionOperator.NOT_CONTAINS,
                        value="accounting"
                    )
                ],
                priority=5
            )
        ]
    )
    policies.append(accounting_module_policy)
    
    return policies


def _get_hr_module_policies() -> List[Policy]:
    """Human Resources module policies"""
    policies = []
    
    # HR Module Access Control
    hr_module_policy = Policy(
        policy_id="hr_module_access_policy",
        name="HR Module Access Control",
        description="Control access to HR resources and employee data",
        version="2.0",
        tenant_id=None,
        rules=[
            PolicyRule(
                rule_id="hr_sensitive_data_protection",
                description="Protect sensitive HR data from unauthorized access",
                effect=Effect.DENY,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["salary", "performance_review", "disciplinary_action", "personal_info"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role_level",
                        operator=ConditionOperator.LT,
                        value=70  # Below STORE_MANAGER level
                    )
                ],
                priority=10
            ),
            PolicyRule(
                rule_id="hr_module_enabled_check",
                description="Only allow access if HR module is enabled",
                effect=Effect.DENY,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="module",
                        operator=ConditionOperator.EQ,
                        value="hr"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="enabled_modules",
                        operator=ConditionOperator.NOT_CONTAINS,
                        value="hr"
                    )
                ],
                priority=5
            )
        ]
    )
    policies.append(hr_module_policy)
    
    return policies


def _get_supply_chain_policies() -> List[Policy]:
    """Supply chain management policies"""
    policies = []
    
    # Supply Chain Module Access
    supply_chain_policy = Policy(
        policy_id="supply_chain_module_policy",
        name="Supply Chain Module Access Control",
        description="Control access to supply chain and procurement resources",
        version="2.0",
        tenant_id=None,
        rules=[
            PolicyRule(
                rule_id="supply_chain_manager_access",
                description="High-level roles can manage supply chain operations",
                effect=Effect.PERMIT,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role_level",
                        operator=ConditionOperator.ROLE_LEVEL_GTE,
                        value=70  # STORE_MANAGER level and above
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["supplier", "purchase_order", "contract", "procurement"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="enabled_modules",
                        operator=ConditionOperator.CONTAINS,
                        value="supply_chain"
                    )
                ],
                priority=20
            ),
            PolicyRule(
                rule_id="supply_chain_module_enabled_check",
                description="Deny access if supply chain module not enabled",
                effect=Effect.DENY,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="module",
                        operator=ConditionOperator.EQ,
                        value="supply_chain"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="enabled_modules",
                        operator=ConditionOperator.NOT_CONTAINS,
                        value="supply_chain"
                    )
                ],
                priority=5
            )
        ]
    )
    policies.append(supply_chain_policy)
    
    return policies


def _get_security_policies() -> List[Policy]:
    """Security and compliance policies"""
    policies = []
    
    # Multi-Factor Authentication Policy
    mfa_policy = Policy(
        policy_id="mfa_security_policy",
        name="Multi-Factor Authentication Requirements",
        description="Require MFA for sensitive operations and high-privilege roles",
        version="2.0",
        tenant_id=None,
        rules=[
            PolicyRule(
                rule_id="mfa_required_admin_actions",
                description="Require MFA for administrative actions",
                effect=Effect.DENY,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.ACTION,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["delete", "admin", "create"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["user", "store", "system_setting", "financial_report"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="mfa_verified",
                        operator=ConditionOperator.NE,
                        value=True
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role_level",
                        operator=ConditionOperator.ROLE_LEVEL_GTE,
                        value=70  # Manager level and above
                    )
                ],
                priority=5
            ),
            PolicyRule(
                rule_id="mfa_required_financial_ops",
                description="Require MFA for financial operations",
                effect=Effect.DENY,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["payment", "refund", "void", "financial_report", "bank_deposit"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="mfa_verified",
                        operator=ConditionOperator.NE,
                        value=True
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="amount",
                        operator=ConditionOperator.GT,
                        value=1000  # Amounts over $1000
                    )
                ],
                priority=8
            )
        ]
    )
    policies.append(mfa_policy)
    
    # IP-Based Access Control
    ip_security_policy = Policy(
        policy_id="ip_security_policy",
        name="IP-Based Access Control",
        description="Restrict access based on IP addresses for sensitive operations",
        version="2.0",
        tenant_id=None,
        rules=[
            PolicyRule(
                rule_id="trusted_ip_admin_access",
                description="Allow admin access only from trusted IP ranges",
                effect=Effect.DENY,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role_level",
                        operator=ConditionOperator.ROLE_LEVEL_GTE,
                        value=80  # TENANT_MANAGER level and above
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.ACTION,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["admin", "delete", "create"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.ENVIRONMENT,
                        attribute_name="client_ip",
                        operator=ConditionOperator.IP_IN_RANGE,
                        value=["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "127.0.0.1"]
                    )
                ],
                priority=12
            )
        ]
    )
    policies.append(ip_security_policy)
    
    # Data Classification Policy
    data_classification_policy = Policy(
        policy_id="data_classification_policy",
        name="Data Classification and Protection",
        description="Protect sensitive data based on classification levels",
        version="2.0",
        tenant_id=None,
        rules=[
            PolicyRule(
                rule_id="pii_protection",
                description="Protect personally identifiable information",
                effect=Effect.DENY,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="classification",
                        operator=ConditionOperator.EQ,
                        value="PII"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role_level",
                        operator=ConditionOperator.LT,
                        value=50  # Below supervisor level
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.ACTION,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["export", "download", "print"]
                    )
                ],
                priority=8
            ),
            PolicyRule(
                rule_id="financial_data_protection",
                description="Protect confidential financial data",
                effect=Effect.DENY,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="classification",
                        operator=ConditionOperator.EQ,
                        value="FINANCIAL_CONFIDENTIAL"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role_level",
                        operator=ConditionOperator.LT,
                        value=70  # Below manager level
                    )
                ],
                priority=8
            )
        ]
    )
    policies.append(data_classification_policy)
    
    return policies


def _get_temporal_policies() -> List[Policy]:
    """Time-based access control policies"""
    policies = []
    
    # Business Hours Policy
    business_hours_policy = Policy(
        policy_id="business_hours_policy",
        name="Business Hours Access Control",
        description="Restrict certain operations outside business hours",
        version="2.0",
        tenant_id=None,
        rules=[
            PolicyRule(
                rule_id="after_hours_financial_restriction",
                description="Restrict high-value financial operations outside business hours",
                effect=Effect.DENY,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.ENVIRONMENT,
                        attribute_name="hour",
                        operator=ConditionOperator.TIME_BETWEEN,
                        value=["22:00", "06:00"]  # 10 PM to 6 AM
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["bank_deposit", "cash_reconciliation", "void"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role_level",
                        operator=ConditionOperator.LT,
                        value=80  # Below TENANT_MANAGER
                    )
                ],
                priority=15
            ),
            PolicyRule(
                rule_id="weekend_admin_restriction",
                description="Restrict admin operations on weekends for lower roles",
                effect=Effect.DENY,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.ENVIRONMENT,
                        attribute_name="weekday",
                        operator=ConditionOperator.WEEKDAY_IN,
                        value=[5, 6]  # Saturday, Sunday
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.ACTION,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["admin", "delete", "create"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["user", "system_setting", "store"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role_level",
                        operator=ConditionOperator.LT,
                        value=90  # Below TENANT_ADMIN
                    )
                ],
                priority=18
            )
        ]
    )
    policies.append(business_hours_policy)
    
    # Session Age Policy
    session_age_policy = Policy(
        policy_id="session_age_policy",
        name="Session Age and Freshness Control",
        description="Require fresh authentication for sensitive operations",
        version="2.0",
        tenant_id=None,
        rules=[
            PolicyRule(
                rule_id="fresh_auth_sensitive_ops",
                description="Require recent authentication for sensitive operations",
                effect=Effect.DENY,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.ACTION,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["delete", "admin", "financial_transfer"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="last_auth_time",
                        operator=ConditionOperator.HOURS_AGO_LT,
                        value=4  # Must have authenticated within 4 hours
                    )
                ],
                priority=12
            )
        ]
    )
    policies.append(session_age_policy)
    
    return policies


def _get_self_service_policies() -> List[Policy]:
    """Self-service and customer access policies"""
    policies = []
    
    # Customer Self-Service Policy
    customer_policy = Policy(
        policy_id="customer_self_service_policy",
        name="Customer Self-Service Access Control",
        description="CUSTOMER role can access their own data and public resources",
        version="2.0",
        tenant_id=None,
        rules=[
            PolicyRule(
                rule_id="customer_self_data_access",
                description="Customers can access their own data",
                effect=Effect.PERMIT,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role",
                        operator=ConditionOperator.EQ,
                        value="CUSTOMER"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["customer_profile", "order_history", "loyalty_points", "receipt"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="owner_id",
                        operator=ConditionOperator.EQ,
                        value="subject.user_id"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.ACTION,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["read", "update"]
                    )
                ],
                priority=30
            ),
            PolicyRule(
                rule_id="customer_public_access",
                description="Customers can access public resources",
                effect=Effect.PERMIT,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role",
                        operator=ConditionOperator.EQ,
                        value="CUSTOMER"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["product_catalog", "store_location", "promotion", "public_announcement"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.ACTION,
                        attribute_name="type",
                        operator=ConditionOperator.EQ,
                        value="read"
                    )
                ],
                priority=30
            ),
            PolicyRule(
                rule_id="customer_no_admin_access",
                description="Customers cannot access administrative resources",
                effect=Effect.DENY,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role",
                        operator=ConditionOperator.EQ,
                        value="CUSTOMER"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["user", "employee", "store", "financial_data", "inventory", "admin_panel"]
                    )
                ],
                priority=25
            )
        ]
    )
    policies.append(customer_policy)
    
    # Employee Self-Service Policy
    employee_self_service_policy = Policy(
        policy_id="employee_self_service_policy",
        name="Employee Self-Service Access Control",
        description="All employees can access their own employment data",
        version="2.0",
        tenant_id=None,
        rules=[
            PolicyRule(
                rule_id="employee_own_data_access",
                description="Employees can view and update their own profile",
                effect=Effect.PERMIT,
                conditions=[
                    PolicyCondition(
                        attribute_type=AttributeType.SUBJECT,
                        attribute_name="role_level",
                        operator=ConditionOperator.ROLE_LEVEL_GTE,
                        value=30  # All employee roles
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["employee_profile", "schedule", "timesheet", "pay_stub", "benefits"]
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.RESOURCE,
                        attribute_name="employee_id",
                        operator=ConditionOperator.EQ,
                        value="subject.user_id"
                    ),
                    PolicyCondition(
                        attribute_type=AttributeType.ACTION,
                        attribute_name="type",
                        operator=ConditionOperator.IN,
                        value=["read", "update"]
                    )
                ],
                priority=25
            )
        ]
    )
    policies.append(employee_self_service_policy)
    
    return policies


# Additional helper functions for policy management
def get_policies_by_module(module_name: str) -> List[Policy]:
    """Get policies specific to a particular module"""
    all_policies = get_default_policies()
    module_policies = []
    
    for policy in all_policies:
        # Check if policy is relevant to the module
        for rule in policy.rules:
            for condition in rule.conditions:
                if (condition.attribute_name == "module" and condition.value == module_name) or \
                   (condition.attribute_name == "type" and module_name in str(condition.value)) or \
                   (condition.attribute_name == "enabled_modules" and condition.value == module_name):
                    module_policies.append(policy)
                    break
    
    return module_policies


def get_policies_by_role(role_name: str) -> List[Policy]:
    """Get policies that apply to a specific role"""
    all_policies = get_default_policies()
    role_policies = []
    
    for policy in all_policies:
        for rule in policy.rules:
            for condition in rule.conditions:
                if condition.attribute_name == "role" and \
                   (condition.value == role_name or 
                    (isinstance(condition.value, list) and role_name in condition.value)):
                    role_policies.append(policy)
                    break
    
    return role_policies


def validate_policy_consistency() -> Dict[str, Any]:
    """Validate that default policies are consistent with role hierarchy"""
    issues = []
    all_policies = get_default_policies()
    
    # Check that all referenced roles exist in hierarchy
    referenced_roles = set()
    for policy in all_policies:
        for rule in policy.rules:
            for condition in rule.conditions:
                if condition.attribute_name == "role":
                    if isinstance(condition.value, list):
                        referenced_roles.update(condition.value)
                    else:
                        referenced_roles.add(condition.value)
    
    missing_roles = referenced_roles - set(ROLE_HIERARCHY.keys())
    if missing_roles:
        issues.append(f"Roles referenced in policies but not in hierarchy: {missing_roles}")
    
    # Check that all modules are covered
    referenced_modules = set()
    for policy in all_policies:
        for rule in policy.rules:
            for condition in rule.conditions:
                if condition.attribute_name == "enabled_modules" or condition.attribute_name == "module":
                    if isinstance(condition.value, list):
                        referenced_modules.update(condition.value)
                    else:
                        referenced_modules.add(condition.value)
    
    missing_modules = set(ORGANIZATION_MODULES.keys()) - referenced_modules
    if missing_modules:
        issues.append(f"Modules not covered by policies: {missing_modules}")
    
    return {
        "valid": len(issues) == 0,
        "issues": issues,
        "total_policies": len(all_policies),
        "referenced_roles": len(referenced_roles),
        "referenced_modules": len(referenced_modules)
    }


async def load_default_policies_to_engine(policy_engine):
    """Load default policies into the policy engine with validation"""
    policies = get_default_policies()
    loaded_count = 0
    
    for policy in policies:
        try:
            await policy_engine.add_policy(policy)
            loaded_count += 1
        except Exception as e:
            print(f"Failed to load policy {policy.policy_id}: {e}")
    
    return loaded_count


# Export all functions
__all__ = [
    "get_default_policies",
    "get_policies_by_module", 
    "get_policies_by_role",
    "validate_policy_consistency",
    "load_default_policies_to_engine",
]