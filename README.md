# Packet DPI Engine

A high-performance, production-grade **C++17 Deep Packet Inspection (DPI)** engine, security policy firewall, and real-time monitoring system.

---

## Architecture & Stages

| Stage | Module | Status | Description |
| :--- | :--- | :--- | :--- |
| **Stage 1** | **PCAP Reader** | **`COMPLETED`** | Streaming zero-copy PCAP reader with endian-swapped headers, truncated capture safety, and configurable memory bounds. |
| **Stage 2** | **Protocol Parser** | **`COMPLETED`** | Strict bounds-checked, zero-copy L2/L3/L4 parser for Ethernet II, IPv4/IPv6, TCP (options, flags, data offset), and UDP. |
| **Stage 3** | **Flow Tracking Engine** | **`COMPLETED`** | Canonical 5-tuple bidirectional flow tracking, observational TCP state machine, UDP session accounting, and deterministic idle eviction. |
| **Stage 4** | **Layer-7 DPI Engine** | **`COMPLETED`** | Bounded reassembly buffer per flow for TLS 1.2/1.3 SNI extraction, HTTP/1.x Host header parsing, and cycle-safe DNS wire format decoding. |
| **Stage 5** | **Rule & Policy Engine** | **`COMPLETED`** | Priority-ordered JSON rule evaluator supporting IPv4/IPv6 CIDR subnets, port ranges, domain wildcards, and two-stage L3/L4 vs L7 verdicts. |
| **Stage 6** | **Multi-Worker Pipeline** | **`COMPLETED`** | Multi-threaded producer-consumer architecture with zero-allocation flow routing, deterministic flow pinning, and worker-isolated tables. |
| **Stage 7** | **Telemetry & Dashboard** | **`COMPLETED`** | Lock-free thread-safe snapshots, atomic JSON exports, REST API (FastAPI), and a modern dark-mode real-time web dashboard. |
| **Stage 8** | **Threat & Anomaly Engine** | **`COMPLETED`** | Worker-local IDS heuristics: horizontal/vertical port scans, stateful SYN flood tracking, Shannon entropy DNS tunneling/DGA, bounded signature matcher, and ring buffer telemetry. |

---

## Directory Structure

```
packet-dpi-engine/
├── CMakeLists.txt              # Top-level C++17 build configuration
├── include/dpi/                # Public modular headers
│   ├── common/                 # Byte-order and core types
│   ├── packet/                 # PCAP reader and types
│   ├── protocols/              # L2/L3/L4 parsers and ParsedPacket
│   ├── flow/                   # Canonical 5-tuple, state machine, FlowTable
│   ├── dpi/                    # Layer-7 DPI engines (TLS, HTTP, DNS)
│   ├── rules/                  # Security policy and matcher engine
│   ├── pipeline/               # Multi-worker threads and flow router
│   ├── telemetry/              # Lock-free telemetry collector & atomic JSON
│   └── threat/                 # Stage 8 Threat & Anomaly detection engine
├── src/                        # C++ core implementations
├── tests/                      # 9 CTest test suites (100% passing)
├── benchmarks/                 # Pipeline, Telemetry, and Threat benchmarks
├── config/                     # Sample security policy & threat rules
├── scripts/                    # PCAP generators and test scripts
├── dashboard/                  # Telemetry & Security Alerts Dashboard
│   ├── backend/                # FastAPI REST API & safe JSON service
│   ├── frontend/               # Semantic HTML5, CSS, and vanilla JS UI
│   └── tests/                  # Backend pytest test suite (11 tests)
└── docs/                       # Architecture documentation
```

---

## Building and Testing

### Prerequisites
- C++17 compliant compiler (GCC 9+, Clang 10+, or MSVC 2019+)
- CMake 3.16 or newer
- Python 3.9+ with `fastapi`, `uvicorn`, `pydantic`, and `pytest` (for dashboard & backend)

### 1. Build C++ Core and Test Suites
```bash
# Configure build (On Windows MinGW/MSYS2: cmake -G "MinGW Makefiles" -B build -S . -DPACKET_DPI_BUILD_BENCHMARKS=ON)
cmake -B build -S . -DPACKET_DPI_BUILD_BENCHMARKS=ON

# Build all binaries
cmake --build build

# Run complete CTest regression suite (8/8 targets)
ctest --test-dir build --output-on-failure --verbose
```

### 2. Run Benchmarks
```bash
# Stage 6 multi-worker pipeline benchmark
./build/benchmarks/pipeline_benchmark.exe

# Stage 7 telemetry overhead benchmark (without vs with live telemetry)
./build/benchmarks/telemetry_benchmark.exe
```

### 3. Run Backend Test Suite
```bash
python -m pytest dashboard/tests/test_backend.py -v
```

---

## Running the Complete System

### Step 1: Run C++ Packet DPI Engine
```bash
# Generate sample test traffic
python scripts/generate_sample_pcap.py

# Execute engine with multi-worker pipeline and live telemetry export
./build/dpi_engine.exe --pcap sample_traffic.pcap \
                       --rules config/sample_rules.json \
                       --workers 4 \
                       --telemetry-file telemetry_snapshot.json \
                       --max-flows 1000
```

### Step 2: Launch FastAPI Monitoring Dashboard
```bash
# Start backend server
uvicorn dashboard.backend.main:app --host 127.0.0.1 --port 8000 --reload
```

Open your browser and navigate to:
```
http://localhost:8000
```

---

## Security Policy Rules Format

Rules are defined in standard JSON format (`config/sample_rules.json`):
```json
{
  "default_action": "ALLOW",
  "rules": [
    {
      "id": 1,
      "name": "Block Malicious Port 8080",
      "priority": 10,
      "action": "BLOCK",
      "dst_port": "8080"
    },
    {
      "id": 2,
      "name": "Block Malicious Domain",
      "priority": 20,
      "action": "BLOCK",
      "domain": "*.badactor.org"
    },
    {
      "id": 3,
      "name": "Alert High Risk Subnet",
      "priority": 50,
      "action": "ALERT",
      "dst_ip": "198.51.100.0/24"
    }
  ]
}
```

---

## REST API Endpoints

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/health` | `GET` | Engine status, backend uptime, and telemetry file status |
| `/api/metrics` | `GET` | Complete atomic telemetry snapshot |
| `/api/metrics/summary` | `GET` | High-level KPIs (packets, throughput, flows, blocks) |
| `/api/protocols` | `GET` | Layer-4 transport and Layer-7 application breakdown |
| `/api/policies` | `GET` | Blocked packets, alert packets, and verdict statistics |
| `/api/workers` | `GET` | Multi-worker core throughput, queue depths, and load |
| `/api/flows` | `GET` | Paginated flow records with searching and filtering |
| `/api/flows/{flow_id}` | `GET` | Detailed bidirectional statistics for a single flow |
| `/api/alerts` | `GET` | Paginated threat alerts with severity/category filtering and text search |
| `/api/alerts/summary` | `GET` | Security alert counts, severity breakdown, and detector summary |
