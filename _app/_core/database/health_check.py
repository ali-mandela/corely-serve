"""
Enterprise Multi-Tenant Stores Management System - Database Health Monitoring
This module provides comprehensive database health monitoring and diagnostics.
"""

import asyncio
import logging
import time
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import json

from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorCollection
from pymongo.errors import (
    ConnectionFailure,
    ServerSelectionTimeoutError,
    OperationFailure,
)

from app._core.database.connection import get_connection_manager
from app._core.database.session_manager import get_session_manager
from app._core.config.settings import get_settings
from app._core.utils.constants import DatabaseConstants
from app._core.utils.exceptions import DatabaseException


logger = logging.getLogger(__name__)


class HealthStatus(Enum):
    """Health check status levels"""

    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class HealthMetric:
    """Individual health metric"""

    name: str
    value: Any
    status: HealthStatus
    message: str
    threshold: Optional[float] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "status": self.status.value,
            "message": self.message,
            "threshold": self.threshold,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class HealthReport:
    """Comprehensive health report"""

    overall_status: HealthStatus
    metrics: List[HealthMetric]
    summary: Dict[str, Any]
    recommendations: List[str]
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_status": self.overall_status.value,
            "metrics": [metric.to_dict() for metric in self.metrics],
            "summary": self.summary,
            "recommendations": self.recommendations,
            "timestamp": self.timestamp.isoformat(),
        }


class DatabaseHealthChecker:
    """Comprehensive database health monitoring"""

    def __init__(self):
        self.settings = get_settings()
        self._last_check: Optional[datetime] = None
        self._cached_report: Optional[HealthReport] = None
        self._cache_duration = timedelta(seconds=30)

        # Health thresholds
        self.thresholds = {
            "response_time_ms": 1000,  # 1 second
            "slow_query_percentage": 10,  # 10%
            "connection_usage": 80,  # 80%
            "disk_usage_percentage": 85,  # 85%
            "memory_usage_percentage": 90,  # 90%
            "active_transactions": 50,  # 50 concurrent
            "idle_sessions": 100,  # 100 idle sessions
            "replication_lag_ms": 5000,  # 5 seconds
        }

    async def check_health(self, force_refresh: bool = False) -> HealthReport:
        """Perform comprehensive health check"""
        # Return cached result if recent
        if (
            not force_refresh
            and self._cached_report
            and self._last_check
            and datetime.utcnow() - self._last_check < self._cache_duration
        ):
            return self._cached_report

        logger.debug("Performing database health check...")
        start_time = time.time()

        metrics = []
        recommendations = []

        try:
            # Connection health
            connection_metrics = await self._check_connection_health()
            metrics.extend(connection_metrics)

            # Performance health
            performance_metrics = await self._check_performance_health()
            metrics.extend(performance_metrics)

            # Session health
            session_metrics = await self._check_session_health()
            metrics.extend(session_metrics)

            # Storage health
            storage_metrics = await self._check_storage_health()
            metrics.extend(storage_metrics)

            # Replication health (if applicable)
            replication_metrics = await self._check_replication_health()
            metrics.extend(replication_metrics)

            # Index health
            index_metrics = await self._check_index_health()
            metrics.extend(index_metrics)

        except Exception as e:
            logger.error(f"Health check failed: {str(e)}")
            metrics.append(
                HealthMetric(
                    name="health_check_error",
                    value=str(e),
                    status=HealthStatus.CRITICAL,
                    message=f"Health check failed: {str(e)}",
                )
            )

        # Determine overall status
        overall_status = self._determine_overall_status(metrics)

        # Generate recommendations
        recommendations = self._generate_recommendations(metrics)

        # Create summary
        summary = self._create_summary(metrics, start_time)

        # Create report
        report = HealthReport(
            overall_status=overall_status,
            metrics=metrics,
            summary=summary,
            recommendations=recommendations,
        )

        # Cache result
        self._cached_report = report
        self._last_check = datetime.utcnow()

        logger.info(
            f"Health check completed: {overall_status.value} ({len(metrics)} metrics)"
        )
        return report

    async def _check_connection_health(self) -> List[HealthMetric]:
        """Check database connection health"""
        metrics = []

        try:
            manager = await get_connection_manager()
            health_status = manager.get_health_status()

            for pool_name, pool_health in health_status.items():
                # Connection state
                is_connected = pool_health.get("is_healthy", False)
                metrics.append(
                    HealthMetric(
                        name=f"connection_status_{pool_name}",
                        value=is_connected,
                        status=(
                            HealthStatus.HEALTHY
                            if is_connected
                            else HealthStatus.CRITICAL
                        ),
                        message=f"Connection pool {pool_name} is {'healthy' if is_connected else 'unhealthy'}",
                    )
                )

                # Connection pool usage
                pool_info = pool_health.get("connection_pool", {})
                active_connections = pool_info.get("active_operations", 0)
                max_connections = pool_info.get("max_size", 1)
                usage_percentage = (active_connections / max_connections) * 100

                status = HealthStatus.HEALTHY
                if usage_percentage > self.thresholds["connection_usage"]:
                    status = HealthStatus.WARNING
                if usage_percentage > 95:
                    status = HealthStatus.CRITICAL

                metrics.append(
                    HealthMetric(
                        name=f"connection_usage_{pool_name}",
                        value=usage_percentage,
                        status=status,
                        message=f"Connection pool usage: {usage_percentage:.1f}%",
                        threshold=self.thresholds["connection_usage"],
                    )
                )

        except Exception as e:
            metrics.append(
                HealthMetric(
                    name="connection_check_error",
                    value=str(e),
                    status=HealthStatus.CRITICAL,
                    message=f"Failed to check connection health: {str(e)}",
                )
            )

        return metrics

    async def _check_performance_health(self) -> List[HealthMetric]:
        """Check database performance health"""
        metrics = []

        try:
            # Test query response time
            start_time = time.time()
            manager = await get_connection_manager()

            async with manager.get_database() as db:
                await db.command("ping")

            response_time_ms = (time.time() - start_time) * 1000

            status = HealthStatus.HEALTHY
            if response_time_ms > self.thresholds["response_time_ms"]:
                status = HealthStatus.WARNING
            if response_time_ms > self.thresholds["response_time_ms"] * 2:
                status = HealthStatus.CRITICAL

            metrics.append(
                HealthMetric(
                    name="response_time",
                    value=response_time_ms,
                    status=status,
                    message=f"Database response time: {response_time_ms:.1f}ms",
                    threshold=self.thresholds["response_time_ms"],
                )
            )

            # Check slow queries from connection metrics
            health_status = manager.get_health_status()
            for pool_name, pool_health in health_status.items():
                pool_metrics = pool_health.get("metrics", {})

                slow_query_percentage = pool_metrics.get("slow_query_percentage", 0)
                status = HealthStatus.HEALTHY
                if slow_query_percentage > self.thresholds["slow_query_percentage"]:
                    status = HealthStatus.WARNING
                if slow_query_percentage > self.thresholds["slow_query_percentage"] * 2:
                    status = HealthStatus.CRITICAL

                metrics.append(
                    HealthMetric(
                        name=f"slow_queries_{pool_name}",
                        value=slow_query_percentage,
                        status=status,
                        message=f"Slow query percentage: {slow_query_percentage:.1f}%",
                        threshold=self.thresholds["slow_query_percentage"],
                    )
                )

        except Exception as e:
            metrics.append(
                HealthMetric(
                    name="performance_check_error",
                    value=str(e),
                    status=HealthStatus.CRITICAL,
                    message=f"Failed to check performance: {str(e)}",
                )
            )

        return metrics

    async def _check_session_health(self) -> List[HealthMetric]:
        """Check session and transaction health"""
        metrics = []

        try:
            session_manager = await get_session_manager()
            stats = session_manager.get_session_stats()

            # Active sessions
            active_sessions = stats.get("total_active_sessions", 0)
            metrics.append(
                HealthMetric(
                    name="active_sessions",
                    value=active_sessions,
                    status=HealthStatus.HEALTHY,
                    message=f"Active sessions: {active_sessions}",
                )
            )

            # Idle sessions
            idle_sessions = stats.get("idle_sessions", 0)
            status = HealthStatus.HEALTHY
            if idle_sessions > self.thresholds["idle_sessions"]:
                status = HealthStatus.WARNING

            metrics.append(
                HealthMetric(
                    name="idle_sessions",
                    value=idle_sessions,
                    status=status,
                    message=f"Idle sessions: {idle_sessions}",
                    threshold=self.thresholds["idle_sessions"],
                )
            )

            # Active transactions
            active_transactions = stats.get("active_transactions", 0)
            status = HealthStatus.HEALTHY
            if active_transactions > self.thresholds["active_transactions"]:
                status = HealthStatus.WARNING

            metrics.append(
                HealthMetric(
                    name="active_transactions",
                    value=active_transactions,
                    status=status,
                    message=f"Active transactions: {active_transactions}",
                    threshold=self.thresholds["active_transactions"],
                )
            )

        except Exception as e:
            metrics.append(
                HealthMetric(
                    name="session_check_error",
                    value=str(e),
                    status=HealthStatus.CRITICAL,
                    message=f"Failed to check session health: {str(e)}",
                )
            )

        return metrics

    async def _check_storage_health(self) -> List[HealthMetric]:
        """Check database storage health"""
        metrics = []

        try:
            manager = await get_connection_manager()
            async with manager.get_database() as db:
                # Get database statistics
                stats = await db.command("dbStats")

                # Database size
                db_size_mb = stats.get("dataSize", 0) / (1024 * 1024)
                metrics.append(
                    HealthMetric(
                        name="database_size_mb",
                        value=db_size_mb,
                        status=HealthStatus.HEALTHY,
                        message=f"Database size: {db_size_mb:.1f} MB",
                    )
                )

                # Collection count
                collection_count = stats.get("collections", 0)
                metrics.append(
                    HealthMetric(
                        name="collection_count",
                        value=collection_count,
                        status=HealthStatus.HEALTHY,
                        message=f"Collections: {collection_count}",
                    )
                )

                # Document count
                object_count = stats.get("objects", 0)
                metrics.append(
                    HealthMetric(
                        name="document_count",
                        value=object_count,
                        status=HealthStatus.HEALTHY,
                        message=f"Documents: {object_count:,}",
                    )
                )

                # Index size
                index_size_mb = stats.get("indexSize", 0) / (1024 * 1024)
                metrics.append(
                    HealthMetric(
                        name="index_size_mb",
                        value=index_size_mb,
                        status=HealthStatus.HEALTHY,
                        message=f"Index size: {index_size_mb:.1f} MB",
                    )
                )

        except Exception as e:
            metrics.append(
                HealthMetric(
                    name="storage_check_error",
                    value=str(e),
                    status=HealthStatus.WARNING,
                    message=f"Failed to check storage health: {str(e)}",
                )
            )

        return metrics

    async def _check_replication_health(self) -> List[HealthMetric]:
        """Check replication health (for replica sets)"""
        metrics = []

        try:
            manager = await get_connection_manager()
            async with manager.get_database() as db:
                # Check if this is a replica set
                is_master_result = await db.command("isMaster")

                if is_master_result.get("ismaster") or is_master_result.get(
                    "secondary"
                ):
                    # Get replication status
                    try:
                        repl_status = await db.command("replSetGetStatus")

                        # Check replica set members
                        members = repl_status.get("members", [])
                        healthy_members = sum(
                            1 for m in members if m.get("health") == 1
                        )

                        metrics.append(
                            HealthMetric(
                                name="replica_set_members",
                                value=f"{healthy_members}/{len(members)}",
                                status=(
                                    HealthStatus.HEALTHY
                                    if healthy_members == len(members)
                                    else HealthStatus.WARNING
                                ),
                                message=f"Healthy replica members: {healthy_members}/{len(members)}",
                            )
                        )

                    except OperationFailure:
                        # Not authorized or not in replica set
                        metrics.append(
                            HealthMetric(
                                name="replication_status",
                                value="standalone",
                                status=HealthStatus.HEALTHY,
                                message="Database is running in standalone mode",
                            )
                        )

        except Exception as e:
            metrics.append(
                HealthMetric(
                    name="replication_check_error",
                    value=str(e),
                    status=HealthStatus.WARNING,
                    message=f"Failed to check replication: {str(e)}",
                )
            )

        return metrics

    async def _check_index_health(self) -> List[HealthMetric]:
        """Check index health and usage"""
        metrics = []

        try:
            manager = await get_connection_manager()
            async with manager.get_database() as db:
                # Get list of collections
                collections = await db.list_collection_names()

                total_indexes = 0
                collections_without_indexes = 0

                for collection_name in collections[:10]:  # Check first 10 collections
                    try:
                        collection = db[collection_name]
                        indexes = await collection.list_indexes().to_list(length=None)

                        index_count = len(indexes)
                        total_indexes += index_count

                        # Collections should have at least _id index
                        if index_count <= 1:
                            collections_without_indexes += 1

                    except Exception:
                        continue

                metrics.append(
                    HealthMetric(
                        name="total_indexes",
                        value=total_indexes,
                        status=HealthStatus.HEALTHY,
                        message=f"Total indexes: {total_indexes}",
                    )
                )

                if collections_without_indexes > 0:
                    metrics.append(
                        HealthMetric(
                            name="collections_without_indexes",
                            value=collections_without_indexes,
                            status=HealthStatus.WARNING,
                            message=f"Collections with only _id index: {collections_without_indexes}",
                        )
                    )

        except Exception as e:
            metrics.append(
                HealthMetric(
                    name="index_check_error",
                    value=str(e),
                    status=HealthStatus.WARNING,
                    message=f"Failed to check indexes: {str(e)}",
                )
            )

        return metrics

    def _determine_overall_status(self, metrics: List[HealthMetric]) -> HealthStatus:
        """Determine overall health status from metrics"""
        if not metrics:
            return HealthStatus.UNKNOWN

        has_critical = any(m.status == HealthStatus.CRITICAL for m in metrics)
        has_warning = any(m.status == HealthStatus.WARNING for m in metrics)

        if has_critical:
            return HealthStatus.CRITICAL
        elif has_warning:
            return HealthStatus.WARNING
        else:
            return HealthStatus.HEALTHY

    def _generate_recommendations(self, metrics: List[HealthMetric]) -> List[str]:
        """Generate health recommendations"""
        recommendations = []

        for metric in metrics:
            if metric.status == HealthStatus.CRITICAL:
                if "connection" in metric.name:
                    recommendations.append(
                        "Check database connectivity and network issues"
                    )
                elif "response_time" in metric.name:
                    recommendations.append(
                        "Investigate slow queries and consider adding indexes"
                    )
                elif "memory" in metric.name:
                    recommendations.append(
                        "Consider increasing database memory allocation"
                    )

            elif metric.status == HealthStatus.WARNING:
                if "slow_queries" in metric.name:
                    recommendations.append("Review and optimize slow queries")
                elif "connection_usage" in metric.name:
                    recommendations.append("Consider increasing connection pool size")
                elif "idle_sessions" in metric.name:
                    recommendations.append("Review session cleanup policies")

        return list(set(recommendations))  # Remove duplicates

    def _create_summary(
        self, metrics: List[HealthMetric], start_time: float
    ) -> Dict[str, Any]:
        """Create health check summary"""
        check_duration_ms = (time.time() - start_time) * 1000

        status_counts = {}
        for status in HealthStatus:
            status_counts[status.value] = sum(1 for m in metrics if m.status == status)

        return {
            "check_duration_ms": round(check_duration_ms, 1),
            "total_metrics": len(metrics),
            "status_distribution": status_counts,
            "database_name": self.settings.database.database,
            "check_timestamp": datetime.utcnow().isoformat(),
        }

    async def get_quick_health(self) -> Dict[str, Any]:
        """Get quick health status without full check"""
        try:
            manager = await get_connection_manager()
            health_status = manager.get_health_status()

            is_healthy = all(
                pool_health.get("is_healthy", False)
                for pool_health in health_status.values()
            )

            return {
                "status": "healthy" if is_healthy else "unhealthy",
                "timestamp": datetime.utcnow().isoformat(),
                "pools": {
                    name: {"healthy": pool.get("is_healthy", False)}
                    for name, pool in health_status.items()
                },
            }

        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }


# Global health checker instance
_health_checker: Optional[DatabaseHealthChecker] = None


def get_health_checker() -> DatabaseHealthChecker:
    """Get global health checker instance"""
    global _health_checker
    if _health_checker is None:
        _health_checker = DatabaseHealthChecker()
    return _health_checker


async def check_database_health(force_refresh: bool = False) -> Dict[str, Any]:
    """Check database health - convenience function"""
    try:
        checker = get_health_checker()
        report = await checker.check_health(force_refresh)
        return report.to_dict()
    except Exception as e:
        return {
            "overall_status": "critical",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat(),
        }


async def get_quick_health_status() -> Dict[str, Any]:
    """Get quick health status - convenience function"""
    try:
        checker = get_health_checker()
        return await checker.get_quick_health()
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat(),
        }


# Export all classes and functions
__all__ = [
    # Enums
    "HealthStatus",
    # Data Classes
    "HealthMetric",
    "HealthReport",
    # Core Classes
    "DatabaseHealthChecker",
    # Convenience Functions
    "get_health_checker",
    "check_database_health",
    "get_quick_health_status",
]
