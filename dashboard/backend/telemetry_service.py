import json
import os
import time
from typing import Optional, Dict, Any, List
from .models import TelemetrySnapshotModel, FlowTelemetryModel, PaginatedFlowsResponse, PaginatedAlertsResponse, SecurityAlertModel

class TelemetryService:
    def __init__(self, default_file_path: str = "telemetry_snapshot.json"):
        self.file_path = os.getenv("DPI_TELEMETRY_FILE", default_file_path)
        self._cached_snapshot: Optional[TelemetrySnapshotModel] = None
        self._last_read_mtime: float = 0.0
        self._start_time: float = time.time()

    def get_uptime_seconds(self) -> float:
        return time.time() - self._start_time

    def is_file_available(self) -> bool:
        return os.path.isfile(self.file_path)

    def load_snapshot(self) -> TelemetrySnapshotModel:
        if not os.path.isfile(self.file_path):
            return TelemetrySnapshotModel(
                engine_status="NO_TELEMETRY",
                timestamp_ns=int(time.time() * 1e9)
            )

        try:
            mtime = os.path.getmtime(self.file_path)
            if self._cached_snapshot and mtime == self._last_read_mtime:
                return self._cached_snapshot

            with open(self.file_path, "r", encoding="utf-8") as f:
                content = f.read()

            if not content.strip():
                if self._cached_snapshot:
                    return self._cached_snapshot
                return TelemetrySnapshotModel(engine_status="ENGINE_RUNNING")

            data = json.loads(content)
            snapshot = TelemetrySnapshotModel(**data)
            self._cached_snapshot = snapshot
            self._last_read_mtime = mtime
            return snapshot

        except (json.JSONDecodeError, OSError, ValueError):
            if self._cached_snapshot:
                return self._cached_snapshot
            return TelemetrySnapshotModel(
                engine_status="ENGINE_RUNNING",
                timestamp_ns=int(time.time() * 1e9)
            )

    def get_paginated_flows(
        self,
        page: int = 1,
        page_size: int = 20,
        transport_protocol: Optional[str] = None,
        app_protocol: Optional[str] = None,
        verdict: Optional[str] = None,
        risk_level: Optional[str] = None,
        min_risk_score: Optional[int] = None,
        search: Optional[str] = None
    ) -> PaginatedFlowsResponse:
        snapshot = self.load_snapshot()
        raw_flows = snapshot.flows
        flows = [rf.to_normalized() for rf in raw_flows]

        # 1. Filters
        if transport_protocol and transport_protocol.upper() != "ALL":
            flows = [f for f in flows if f.transport_protocol.upper() == transport_protocol.upper()]

        if app_protocol and app_protocol.upper() != "ALL":
            flows = [f for f in flows if f.app_protocol.upper() == app_protocol.upper()]

        if verdict and verdict.upper() != "ALL":
            flows = [f for f in flows if f.policy_verdict.upper() == verdict.upper()]

        if risk_level and risk_level.upper() != "ALL":
            flows = [f for f in flows if f.risk_level.upper() == risk_level.upper()]

        if min_risk_score is not None and min_risk_score > 0:
            flows = [f for f in flows if f.risk_score >= min_risk_score]

        if search:
            s = search.lower().strip()
            flows = [
                f for f in flows
                if s in f.src_ip.lower()
                or s in f.dst_ip.lower()
                or s in f.host_or_sni.lower()
                or s in f.matched_rule_name.lower()
                or s in f.flow_id.lower()
            ]

        total = len(flows)
        page = max(1, page)
        page_size = max(1, min(100, page_size))
        total_pages = (total + page_size - 1) // page_size if total > 0 else 1

        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        paged_flows = flows[start_idx:end_idx]

        return PaginatedFlowsResponse(
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            flows=paged_flows
        )

    def get_paginated_alerts(
        self,
        page: int = 1,
        page_size: int = 20,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        search: Optional[str] = None
    ) -> PaginatedAlertsResponse:
        snapshot = self.load_snapshot()
        alerts = list(snapshot.alerts)

        if severity and severity.upper() != "ALL":
            alerts = [a for a in alerts if a.severity.upper() == severity.upper()]

        if category and category.upper() != "ALL":
            alerts = [a for a in alerts if a.category.upper() == category.upper()]

        if search:
            s = search.lower().strip()
            alerts = [
                a for a in alerts
                if s in a.signature.lower()
                or s in a.description.lower()
                or s in a.src_ip.lower()
                or s in a.dst_ip.lower()
                or s in a.trigger_reason.lower()
                or s in a.matched_snippet.lower()
            ]

        total = len(alerts)
        page = max(1, page)
        page_size = max(1, min(100, page_size))
        total_pages = (total + page_size - 1) // page_size if total > 0 else 1

        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        paged_alerts = alerts[start_idx:end_idx]

        return PaginatedAlertsResponse(
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            alerts=paged_alerts
        )

    def get_flow_by_id(self, flow_id: str) -> Optional[FlowTelemetryModel]:
        snapshot = self.load_snapshot()
        for rf in snapshot.flows:
            f = rf.to_normalized()
            if f.flow_id == flow_id or rf.id == flow_id:
                return f
        return None
