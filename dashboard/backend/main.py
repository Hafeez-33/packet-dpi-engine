import os
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from typing import Optional, Dict, Any

from .models import (
    TelemetrySnapshotModel,
    HealthResponse,
    PaginatedFlowsResponse,
    FlowTelemetryModel,
    PaginatedAlertsResponse,
    SecurityAlertModel,
    ThreatMetricsModel
)
from .telemetry_service import TelemetryService

app = FastAPI(
    title="Packet DPI Engine Telemetry API",
    description="REST API for real-time telemetry, flow inspection, security policies, and multi-worker pipeline metrics.",
    version="1.0.0"
)

# Enable CORS for local development & frontend clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

telemetry_service = TelemetryService()

@app.get("/api/health", response_model=HealthResponse)
def get_health():
    snapshot = telemetry_service.load_snapshot()
    return HealthResponse(
        status="healthy",
        engine_status=snapshot.engine_status,
        backend_uptime_seconds=telemetry_service.get_uptime_seconds(),
        telemetry_file_exists=telemetry_service.is_file_available(),
        telemetry_file_path=telemetry_service.file_path,
        last_telemetry_update_ms=int(snapshot.timestamp_ns / 1_000_000)
    )

@app.get("/api/metrics", response_model=TelemetrySnapshotModel)
def get_metrics():
    return telemetry_service.load_snapshot()

@app.get("/api/metrics/summary")
def get_metrics_summary():
    s = telemetry_service.load_snapshot()
    classified = (s.protocols.application.tls + 
                  s.protocols.application.http + 
                  s.protocols.application.dns)
    return {
        "engine_status": s.engine_status,
        "timestamp_ns": s.timestamp_ns,
        "duration_sec": s.duration_sec,
        "total_packets": s.traffic.total_packets,
        "total_bytes": s.traffic.total_bytes,
        "packets_per_sec": s.traffic.packets_per_sec,
        "bytes_per_sec": s.traffic.bytes_per_sec,
        "mb_per_sec": s.traffic.mb_per_sec,
        "total_flows": s.flows_summary.total_flows,
        "active_flows": s.flows_summary.active_flows,
        "completed_flows": s.flows_summary.completed_flows,
        "classified_flows": classified,
        "blocked_packets": s.policy.blocked_packets,
        "blocked_flows": s.policy.blocked_flows,
        "worker_count": len(s.workers)
    }

@app.get("/api/protocols")
def get_protocol_distribution():
    s = telemetry_service.load_snapshot()
    classified = (s.protocols.application.tls + 
                  s.protocols.application.http + 
                  s.protocols.application.dns)
    return {
        "transport": {
            "tcp": s.protocols.transport.tcp,
            "udp": s.protocols.transport.udp,
            "other": s.protocols.transport.other,
        },
        "application": {
            "tls": s.protocols.application.tls,
            "http": s.protocols.application.http,
            "dns": s.protocols.application.dns,
            "unknown": s.protocols.application.unknown,
            "classified_total": classified
        }
    }

@app.get("/api/policies")
def get_policy_metrics():
    s = telemetry_service.load_snapshot()
    return {
        "blocked_packets": s.policy.blocked_packets,
        "alert_packets": s.policy.alert_packets,
        "blocked_flows": s.policy.blocked_flows,
        "allowed_flows": s.policy.allowed_flows,
    }

@app.get("/api/workers")
def get_worker_metrics():
    s = telemetry_service.load_snapshot()
    return {
        "worker_count": len(s.workers),
        "workers": s.workers
    }

@app.get("/api/flows", response_model=PaginatedFlowsResponse)
def get_flows(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    transport: Optional[str] = Query(None, description="Transport protocol: ALL, TCP, UDP, Other"),
    app: Optional[str] = Query(None, description="L7 protocol: ALL, TLS, HTTP, DNS, Unknown"),
    verdict: Optional[str] = Query(None, description="Policy verdict: ALL, ALLOW, BLOCK, ALERT"),
    search: Optional[str] = Query(None, description="Search term for IP, hostname, or rule")
):
    return telemetry_service.get_paginated_flows(
        page=page,
        page_size=page_size,
        transport_protocol=transport,
        app_protocol=app,
        verdict=verdict,
        search=search
    )

@app.get("/api/alerts", response_model=PaginatedAlertsResponse)
def get_alerts(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    severity: Optional[str] = Query(None, description="Severity: ALL, CRITICAL, HIGH, MEDIUM, LOW, INFO"),
    category: Optional[str] = Query(None, description="Threat category"),
    search: Optional[str] = Query(None, description="Search keyword")
):
    return telemetry_service.get_paginated_alerts(
        page=page,
        page_size=page_size,
        severity=severity,
        category=category,
        search=search
    )

@app.get("/api/alerts/summary")
def get_alerts_summary():
    s = telemetry_service.load_snapshot()
    return s.threat_metrics

@app.get("/api/flows/{flow_id}", response_model=FlowTelemetryModel)
def get_flow_details(flow_id: str):
    flow = telemetry_service.get_flow_by_id(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail=f"Flow ID '{flow_id}' not found")
    return flow

# Serve static frontend files
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

    @app.get("/")
    def serve_frontend_root():
        return FileResponse(os.path.join(frontend_dir, "index.html"))

    @app.get("/{full_path:path}")
    def serve_frontend_file(full_path: str):
        target_path = os.path.join(frontend_dir, full_path)
        if os.path.isfile(target_path):
            return FileResponse(target_path)
        return FileResponse(os.path.join(frontend_dir, "index.html"))
