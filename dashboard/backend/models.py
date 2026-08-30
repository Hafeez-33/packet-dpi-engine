from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class WorkerStatsModel(BaseModel):
    worker_id: int
    packets_processed: int = 0
    bytes_processed: int = 0
    flows_created: int = 0
    blocked_packets: int = 0
    alert_packets: int = 0
    dpi_classified_flows: int = 0
    malformed_packets: int = 0
    queue_size: int = 0

class FlowTelemetryModel(BaseModel):
    flow_id: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    transport_protocol: str = "TCP"
    app_protocol: str = "Unknown"
    host_or_sni: str = ""
    tcp_state: str = "Unknown"
    policy_verdict: str = "ALLOW"
    matched_rule_name: str = ""
    is_blocked: bool = False
    packets_forward: int = 0
    packets_reverse: int = 0
    bytes_forward: int = 0
    bytes_reverse: int = 0
    duration_ms: int = 0

class TrafficMetrics(BaseModel):
    total_packets: int = 0
    total_bytes: int = 0
    packets_per_sec: float = 0.0
    bytes_per_sec: float = 0.0
    mb_per_sec: float = 0.0

class FlowMetrics(BaseModel):
    total_flows: int = 0
    active_flows: int = 0
    completed_flows: int = 0

class TransportProtocols(BaseModel):
    tcp: int = 0
    udp: int = 0
    other: int = 0

class AppProtocols(BaseModel):
    tls: int = 0
    http: int = 0
    dns: int = 0
    unknown: int = 0

class ProtocolDistributionModel(BaseModel):
    transport: TransportProtocols = Field(default_factory=TransportProtocols)
    application: AppProtocols = Field(default_factory=AppProtocols)

class PolicyMetrics(BaseModel):
    blocked_packets: int = 0
    alert_packets: int = 0
    blocked_flows: int = 0
    allowed_flows: int = 0

class ErrorsModel(BaseModel):
    malformed_packets: int = 0
    unroutable_packets: int = 0

class RawFlowModel(BaseModel):
    id: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "TCP"
    app_protocol: str = "Unknown"
    host: str = ""
    tcp_state: str = "Unknown"
    verdict: str = "ALLOW"
    matched_rule: str = ""
    packets_fwd: int = 0
    packets_rev: int = 0
    bytes_fwd: int = 0
    bytes_rev: int = 0
    duration_ms: int = 0
    is_blocked: bool = False

    def to_normalized(self) -> FlowTelemetryModel:
        return FlowTelemetryModel(
            flow_id=self.id,
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            src_port=self.src_port,
            dst_port=self.dst_port,
            transport_protocol=self.protocol,
            app_protocol=self.app_protocol,
            host_or_sni=self.host,
            tcp_state=self.tcp_state,
            policy_verdict=self.verdict,
            matched_rule_name=self.matched_rule,
            is_blocked=self.is_blocked,
            packets_forward=self.packets_fwd,
            packets_reverse=self.packets_rev,
            bytes_forward=self.bytes_fwd,
            bytes_reverse=self.bytes_rev,
            duration_ms=self.duration_ms
        )

class TelemetrySnapshotModel(BaseModel):
    engine_status: str = "NO_TELEMETRY"
    timestamp_ns: int = 0
    duration_sec: float = 0.0
    traffic: TrafficMetrics = Field(default_factory=TrafficMetrics)
    flows_summary: FlowMetrics = Field(default_factory=FlowMetrics)
    protocols: ProtocolDistributionModel = Field(default_factory=ProtocolDistributionModel)
    policy: PolicyMetrics = Field(default_factory=PolicyMetrics)
    errors: ErrorsModel = Field(default_factory=ErrorsModel)
    workers: List[WorkerStatsModel] = Field(default_factory=list)
    flows: List[RawFlowModel] = Field(default_factory=list)

class HealthResponse(BaseModel):
    status: str = "healthy"
    engine_status: str = "NO_TELEMETRY"
    backend_uptime_seconds: float = 0.0
    telemetry_file_exists: bool = False
    telemetry_file_path: str = ""
    last_telemetry_update_ms: int = 0

class PaginatedFlowsResponse(BaseModel):
    total: int
    page: int
    page_size: int
    total_pages: int
    flows: List[FlowTelemetryModel]
