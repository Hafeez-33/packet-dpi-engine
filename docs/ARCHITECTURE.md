# System Architecture & Technical Specification

The **Packet DPI Engine** is a high-throughput, multi-threaded C++17 Deep Packet Inspection (DPI) system designed for wire-speed network protocol analysis, flow reassembly, Layer-7 application classification, and rule-based traffic enforcement.

---

## 1. End-to-End Processing Pipeline

The packet processing lifecycle flows through seven discrete, decoupled pipeline stages:

```
┌─────────────────┐
│   PCAP Reader   │  (Binary parser, endian conversion, buffered packet ingestion)
└────────┬────────┘
         │ Raw bytes
         ▼
┌─────────────────┐
│ L2/L3/L4 Parser │  (Ethernet, IPv4/IPv6, TCP/UDP headers; zero-copy bounds checking)
└────────┬────────┘
         │ Parsed metadata & 5-tuple
         ▼
┌─────────────────┐
│  Flow Tracking  │  (Canonical 5-tuple, state machine: NEW -> ESTABLISHED -> CLOSED)
└────────┬────────┘
         │ Active flow context
         ▼
┌─────────────────┐
│   L7 DPI Engine │  (TLS 1.2/1.3 SNI decoder, HTTP Host parser, DNS query extractor)
└────────┬────────┘
         │ App classification & domain
         ▼
┌─────────────────┐
│   Rule Engine   │  (Policy ACL: IP prefixes, wildcard domains, ports, applications)
└────────┬────────┘
         │ Action: FORWARD / DROP / LOG
         ▼
┌─────────────────┐
│ Worker Pipeline │  (Consistent flow hashing, multi-core worker queues, output writer)
└────────┬────────┘
         │ Telemetry counters
         ▼
┌─────────────────┐
│ Metrics & API   │  (Lock-free atomic metrics, Prometheus/JSON exporter, FastAPI Dashboard)
└─────────────────┘
```

---

## 2. Component Breakdown & Design Principles

### Stage 1: PCAP Reader [IMPLEMENTED]
- **Role**: Reads standard `.pcap` capture streams in native or swapped byte order.
- **Safety**: Strict validation of the 24-byte Global Header and 16-byte Packet Headers, isolated version 2.4 validation, max packet memory limit.
- **Performance**: Streaming RAII binary I/O.

### Stage 2: L2/L3/L4 Protocol Parser [PLANNED]
- **Role**: Slices raw Ethernet frames, IPv4/IPv6 packets, and TCP/UDP transport segments.
- **Safety**: Safe endian-aware deserialization (`PortableNet` / `std::endian`), strict offset arithmetic, and zero unaligned pointer casts.
- **Payload Extraction**: Computes transport header lengths and provides `std::string_view` / byte spans for upper-layer inspection.

### Stage 3: Flow Engine & State Tracking
- **Role**: Groups individual packets into bidirectional network conversations ("flows").
- **Canonical 5-Tuple**: Normalizes `(src_ip, dst_ip, src_port, dst_port, protocol)` such that packets traveling in both directions map to the exact same hash bucket and worker thread.
- **TCP State Machine**: Tracks TCP handshake flags (`SYN`, `SYN-ACK`, `ACK`, `FIN`, `RST`) and transitions flows between `NEW`, `ESTABLISHED`, `CLASSIFIED`, and `CLOSED`.
- **Flow Eviction**: LRU and timeout-based eviction for inactive or terminated sessions.

### Stage 4: Layer-7 Deep Packet Inspection (DPI)
- **TLS SNI Decoder**: Inspects the TLS Handshake Record (Content Type `0x16`, Handshake Type `0x01` ClientHello) and parses the Extension list for Server Name Indication (Type `0x0000`).
- **HTTP Host Parser**: Case-insensitive parsing of `Host:` headers in cleartext HTTP/1.1 requests.
- **DNS Decoder**: RFC 1035 wire-format decoder extracting queried domain names.
- **Classification Engine**: Maps extracted server names and protocols into a high-level application taxonomy (e.g., Google, YouTube, GitHub, Discord, Netflix).

### Stage 5: Rule & Policy Engine
- **Role**: Evaluates traffic against configurable access control lists (ACLs).
- **Rule Types**:
  - Exact IP and CIDR subnet blocking
  - Wildcard domain rules (e.g., `*.tiktok.com`, `ads.*.com`)
  - Transport port blocking
  - Application-level policy enforcement (e.g., block all `AppType::BitTorrent`)
- **Concurreny**: Read-heavy optimizations with `std::shared_mutex` for dynamic rule updates.

### Stage 6: Multi-threaded Worker Pipeline
- **Architecture**: Ingestion $\rightarrow$ Load Balancer dispatchers $\rightarrow$ Fast-Path DPI worker threads $\rightarrow$ Output sink.
- **Consistent Flow Pinning**: Consistent hashing of the canonical 5-tuple guarantees that all packets for a flow are processed sequentially by the exact same worker core, avoiding cross-thread flow table contention.
- **Bounded Queues**: Thread-safe bounded queues with backpressure and graceful drain on termination.

### Stage 7: Telemetry, Metrics & Dashboard
- **Lock-free Counters**: Atomic counters for total packets, total bytes, drops, forwards, protocol breakdown, and classification hits.
- **FastAPI Integration**: REST API endpoint exposing live throughput and flow state to the web UI.

---

## 3. Directory Layout

```
packet-dpi-engine/
├── CMakeLists.txt
├── README.md
├── LICENSE
├── .gitignore
├── include/dpi/
│   ├── packet/        # Raw packet representations & memory buffers
│   ├── protocols/     # L2, L3, L4 protocol header decoders
│   ├── flow/          # FiveTuple, FlowTable, FlowState
│   ├── dpi/           # TLS SNI, HTTP, DNS decoders
│   ├── rules/         # RuleEngine and ACL policies
│   ├── pipeline/      # Thread queues, LoadBalancer, WorkerPool
│   └── metrics/       # Atomic telemetry and counters
├── src/
│   ├── version.cpp
│   └── main.cpp
├── tests/
│   ├── CMakeLists.txt
│   └── main_test.cpp
├── benchmarks/
├── configs/
│   └── rules_example.json
├── docs/
│   └── ARCHITECTURE.md
└── dashboard/
```
