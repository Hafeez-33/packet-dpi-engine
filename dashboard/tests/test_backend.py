import json
import os
import pytest
from fastapi.testclient import TestClient
from dashboard.backend.main import app, telemetry_service

client = TestClient(app)

SAMPLE_SNAPSHOT = {
    "engine_status": "ENGINE_RUNNING",
    "timestamp_ns": 1600000000000000000,
    "duration_sec": 5.0,
    "traffic": {
        "total_packets": 1000,
        "total_bytes": 650000,
        "packets_per_sec": 200.0,
        "bytes_per_sec": 130000.0,
        "mb_per_sec": 0.12
    },
    "flows_summary": {
        "total_flows": 10,
        "active_flows": 8,
        "completed_flows": 2
    },
    "protocols": {
        "transport": {
            "tcp": 6,
            "udp": 4,
            "other": 0
        },
        "application": {
            "tls": 4,
            "http": 2,
            "dns": 1,
            "unknown": 3
        }
    },
    "policy": {
        "blocked_packets": 15,
        "alert_packets": 5,
        "blocked_flows": 2,
        "allowed_flows": 8
    },
    "errors": {
        "malformed_packets": 2,
        "unroutable_packets": 0
    },
    "workers": [
        {
            "worker_id": 0,
            "packets_processed": 500,
            "bytes_processed": 325000,
            "flows_created": 5,
            "blocked_packets": 8,
            "alert_packets": 3,
            "dpi_classified_flows": 4,
            "malformed_packets": 1,
            "queue_size": 1
        },
        {
            "worker_id": 1,
            "packets_processed": 500,
            "bytes_processed": 325000,
            "flows_created": 5,
            "blocked_packets": 7,
            "alert_packets": 2,
            "dpi_classified_flows": 3,
            "malformed_packets": 1,
            "queue_size": 0
        }
    ],
    "flows": [
        {
            "id": "10.0.0.1:54321 <-> 1.1.1.1:443 [TCP]",
            "src_ip": "10.0.0.1",
            "dst_ip": "1.1.1.1",
            "src_port": 54321,
            "dst_port": 443,
            "protocol": "TCP",
            "app_protocol": "TLS",
            "host": "cloudflare.com",
            "tcp_state": "ESTABLISHED",
            "verdict": "ALLOW",
            "matched_rule": "Default Allow",
            "packets_fwd": 50,
            "packets_rev": 50,
            "bytes_fwd": 15000,
            "bytes_rev": 35000,
            "duration_ms": 2500,
            "is_blocked": False
        },
        {
            "id": "10.0.0.2:50000 <-> 192.168.1.100:8080 [TCP]",
            "src_ip": "10.0.0.2",
            "dst_ip": "192.168.1.100",
            "src_port": 50000,
            "dst_port": 8080,
            "protocol": "TCP",
            "app_protocol": "HTTP",
            "host": "malicious-site.org",
            "tcp_state": "CLOSED",
            "verdict": "BLOCK",
            "matched_rule": "Block Malicious Domain",
            "packets_fwd": 1,
            "packets_rev": 0,
            "bytes_fwd": 150,
            "bytes_rev": 0,
            "duration_ms": 10,
            "is_blocked": True
        }
    ]
}

@pytest.fixture(autouse=True)
def setup_teardown_snapshot_file():
    test_filepath = "test_backend_telemetry.json"
    telemetry_service.file_path = test_filepath
    with open(test_filepath, "w", encoding="utf-8") as f:
        json.dump(SAMPLE_SNAPSHOT, f)
    yield
    if os.path.exists(test_filepath):
        os.remove(test_filepath)

def test_health_endpoint():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["engine_status"] == "ENGINE_RUNNING"
    assert data["telemetry_file_exists"] is True

def test_metrics_endpoint():
    res = client.get("/api/metrics")
    assert res.status_code == 200
    data = res.json()
    assert data["engine_status"] == "ENGINE_RUNNING"
    assert data["traffic"]["total_packets"] == 1000
    assert len(data["workers"]) == 2
    assert len(data["flows"]) == 2

def test_metrics_summary_endpoint():
    res = client.get("/api/metrics/summary")
    assert res.status_code == 200
    data = res.json()
    assert data["total_packets"] == 1000
    assert data["total_flows"] == 10
    assert data["blocked_flows"] == 2
    assert data["worker_count"] == 2

def test_protocols_endpoint():
    res = client.get("/api/protocols")
    assert res.status_code == 200
    data = res.json()
    assert data["transport"]["tcp"] == 6
    assert data["transport"]["udp"] == 4
    assert data["application"]["tls"] == 4
    assert data["application"]["http"] == 2

def test_policies_endpoint():
    res = client.get("/api/policies")
    assert res.status_code == 200
    data = res.json()
    assert data["blocked_packets"] == 15
    assert data["blocked_flows"] == 2
    assert data["allowed_flows"] == 8

def test_workers_endpoint():
    res = client.get("/api/workers")
    assert res.status_code == 200
    data = res.json()
    assert data["worker_count"] == 2
    assert data["workers"][0]["packets_processed"] == 500

def test_flows_pagination_and_filtering():
    res_tcp = client.get("/api/flows?transport=TCP")
    assert res_tcp.status_code == 200
    assert res_tcp.json()["total"] == 2

    res_block = client.get("/api/flows?verdict=BLOCK")
    assert res_block.status_code == 200
    assert res_block.json()["total"] == 1
    assert res_block.json()["flows"][0]["policy_verdict"] == "BLOCK"

    res_search = client.get("/api/flows?search=cloudflare")
    assert res_search.status_code == 200
    assert res_search.json()["total"] == 1
    assert res_search.json()["flows"][0]["host_or_sni"] == "cloudflare.com"

def test_single_flow_lookup():
    flow_id = "10.0.0.1:54321 <-> 1.1.1.1:443 [TCP]"
    res = client.get(f"/api/flows/{flow_id}")
    assert res.status_code == 200
    assert res.json()["src_ip"] == "10.0.0.1"

    res_404 = client.get("/api/flows/nonexistent-flow")
    assert res_404.status_code == 404

def test_missing_and_corrupted_telemetry_file():
    telemetry_service.file_path = "nonexistent_telemetry.json"
    telemetry_service._cached_snapshot = None
    res_missing = client.get("/api/health")
    assert res_missing.status_code == 200
    assert res_missing.json()["engine_status"] == "NO_TELEMETRY"

    corrupt_file = "corrupt_telemetry.json"
    telemetry_service.file_path = corrupt_file
    with open(corrupt_file, "w", encoding="utf-8") as f:
        f.write("{ INVALID JSON DATA ....")
    
    res_corrupt = client.get("/api/metrics")
    assert res_corrupt.status_code == 200
    assert res_corrupt.json()["engine_status"] == "ENGINE_RUNNING"
    os.remove(corrupt_file)
