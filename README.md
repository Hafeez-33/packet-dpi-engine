# Packet DPI Engine

A high-performance, production-oriented **C++17 Deep Packet Inspection (DPI)** engine and network traffic analyzer.

## Overview

**Packet DPI Engine** inspects network packet payloads at wire speed to extract application protocols, track bidirectional network flows, detect TLS Server Name Indication (SNI) and cleartext HTTP/DNS headers, and enforce granular firewall policy rules.

### Key Capabilities
- **Stage 1 PCAP Reader [IMPLEMENTED]**: Streaming RAII classic `.pcap` parser with native & byte-swapped endian support, validation, truncated stream safety, and configurable payload memory safety limits.
- **Stage 2 Protocol Parser [IMPLEMENTED]**: Bounds-checked, alignment-safe parsing for Ethernet II, IPv4 (with IHL options & fragmentation handling), IPv6 base headers, TCP (flags, data offset, options, zero-copy payload views), and UDP with rigorous error reporting.
- **Stage 3 Bidirectional Flow Engine [PLANNED]**: Canonical 5-tuple flow state machine with TCP handshake tracking.
- **Layer-7 Inspection [PLANNED]**: TLS 1.2/1.3 SNI extraction, HTTP `Host:` decoding, DNS query resolution.
- **Policy & Rule Engine [PLANNED]**: High-speed filtering by IP, domain wildcard, application type, and transport port.
- **Multi-threaded Pipeline [PLANNED]**: Consistent flow hashing across fast-path worker threads with lock-free statistics.
- **FastAPI Telemetry Dashboard [PLANNED]**: Real-time traffic breakdown and monitoring interface.

---

## Directory Structure

```
packet-dpi-engine/
├── CMakeLists.txt        # Top-level build configuration
├── include/dpi/          # Public C++ modular headers
├── src/                  # Implementation sources
├── tests/                # Unit and integration test suites
├── benchmarks/           # Performance microbenchmarks
├── configs/              # Sample JSON/TXT filtering rules
├── docs/                 # Architecture & design documentation
└── dashboard/            # FastAPI metrics and monitoring backend
```

---

## Building the Project

### Prerequisites
- C++17 compliant compiler (GCC 9+, Clang 10+, or MSVC 2019+)
- CMake 3.16 or newer
- Windows (MSYS2 UCRT64 / MinGW-w64 or Visual Studio) or Linux / macOS

### Quick Start

```bash
# Configure build
cmake -B build -S .

# Build all targets
cmake --build build

# Run unit test suite
ctest --test-dir build --output-on-failure
```

---

## Documentation

For full architectural specifications, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
