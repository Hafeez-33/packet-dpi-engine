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

### Stage 2: L2/L3/L4 Protocol Parser [IMPLEMENTED]
- **Role**: Slices raw Ethernet frames, IPv4/IPv6 packets, and TCP/UDP transport segments into a canonical `ParsedPacket`.
- **Supported Protocols**:
  - **Ethernet II**: Destination/Source MAC addresses, EtherType dispatch (`0x0800` IPv4, `0x86DD` IPv6, with `0x0806` ARP etc. detected).
  - **IPv4**: Version, IHL, DSCP/ECN, total length, identification, control flags (DF, MF), fragment offset (in 8-byte units and bytes), TTL, protocol, checksum, 32-bit source/destination IP addresses, and IP header options slicing.
  - **IPv4 Fragmentation**: Flags and fragment offset are explicitly exposed. Initial fragments (`MF=1, offset=0`) parse L4 headers; non-initial fragments (`offset > 0`) are safely identified (`L4Type::IPv4Fragment`, `ProtocolErrorCode::IPv4FragmentedNonInitial`) and prevented from blind L4 parsing.
  - **IPv6**: Base 40-byte header parsing (Version=6, Traffic Class, 20-bit Flow Label, Payload Length, Next Header, Hop Limit, 128-bit source/destination IP addresses). Direct Next Header TCP/UDP parsing supported. *(Note: Full IPv6 extension-header chain traversal is a documented limitation for a subsequent stage).*
  - **TCP**: Source/destination ports, sequence and acknowledgment numbers, Data Offset (in 32-bit words), flags (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR), window size, checksum, urgent pointer, TCP options slicing, and zero-copy L7 payload view.
  - **UDP**: Source/destination ports, length, checksum, and zero-copy L7 payload view.
- **Safety & Alignment**: Bounds-checked before every read or slice; explicit endian-aware byte deserialization (`read_u8`, `read_u16_be`, `read_u32_be`); zero struct `reinterpret_cast` avoiding unaligned pointer faults.
- **Malformed Packet Handling**: Strict validation rejects truncated or corrupted headers with specific error codes (`ProtocolErrorCode`).

### Stage 3: Flow Engine & State Tracking [IMPLEMENTED]
- **Role**: Groups individual packets into bidirectional network conversations ("flows") and tracks connection lifecycles and metrics.
- **Canonical 5-Tuple Normalization**: Normalizes `(src_ip, src_port, dst_ip, dst_port, protocol)` via `FlowKey` and unified `IPAddress` (IPv4 and IPv6) such that forward and reverse traffic map deterministically to the exact same hash bucket.
- **Observational TCP State Machine**: Robust observational tracking of connection handshakes (`SYN` $\to$ `SYN-ACK` $\to$ `ACK` $\to$ `ESTABLISHED`), data transfers, mid-stream pickups (packets observed without initial SYN), retransmissions, and teardown (`FIN` from either side, simultaneous FINs, and `RST` from any state).
- **UDP Flow Tracking**: Seamless bidirectional session tracking and state transitions (`Active` $\to$ `Established`).
- **Directional Metrics**: Per-flow forward and reverse counters for total packets, wire bytes, application payload bytes, first-seen/last-seen timestamps, and duration.
- **Timestamp Normalization**: Uniform microsecond resolution (`normalize_timestamp_us`) handling both microsecond and nanosecond PCAP capture headers.
- **Deterministic Eviction**: Idle expiration (`cleanup_expired`) with configurable protocol-specific timeouts (`FlowTimeoutConfig`) without background thread overhead.
- **Zero-Copy & Memory Footprint**: Flow records (`FlowEntry`) track only metadata, metrics, and state machine transitions; raw packet payloads are never buffered.

### Stage 4: Layer-7 Deep Packet Inspection (DPI) [IMPLEMENTED]
- **Role**: Dissects application-layer transport payloads to identify protocols and extract hostnames, domains, and session metadata.
- **TLS ClientHello & SNI Decoder**: Inspects TLS Record Layer (Content Type `0x16`, Handshake Type `0x01` ClientHello) across TLS 1.2 and TLS 1.3, navigating cipher suites, compression methods, and extensions to safely extract Server Name Indication (SNI, Type `0x0000`).
- **HTTP/1.x Request Parser**: Parses textual request lines (`GET`, `POST`, `HEAD`, `PUT`, `DELETE`, `OPTIONS`, `PATCH`, `CONNECT`, `TRACE`) and performs case-insensitive extraction and port-trimming of `Host:` headers bounded to the headers block.
- **Cycle-Safe DNS Wire Parser**: RFC 1035 wire-format decoder extracting question section domain names (`QNAME`, `QTYPE`, `QCLASS`) with visited-offset cycle bitset detection, boundary checks, and a strict 5-jump limit to prevent malicious compression pointer loops.
- **Bounded Per-Flow DPI Reassembly**: Operates a temporary, configurable reassembly buffer (default 8 KB) per flow to inspect fragmented or split application payloads across multi-packet TCP segments.
- **Zero Memory Bloat & Fast-Path Optimization**: As soon as a flow is classified or the buffer limit is reached, temporary reassembly memory is immediately cleared and deallocated (`shrink_to_fit()`), storing only compact `L7Metadata`. Classified flows bypass DPI on subsequent packets.

### Stage 5: Rule & Policy Engine [IMPLEMENTED]
- **Role**: Evaluates traffic against configurable access control lists (ACLs) and security policies with deterministic priority-based resolution.
- **Rule Matching Criteria**:
  - **IPv4 / IPv6 Exact & CIDR Subnets** (`IpMatcher`): Zero heap allocation bitmask evaluation (`192.168.1.0/24`, `2001:db8::/32`).
  - **Port Ranges & Lists** (`PortMatcher`): Single ports, ranges (`8000-8080`), and comma-separated lists (`80,443,8080`).
  - **Case-Insensitive Domain Wildcards** (`DomainMatcher`): Exact domains, suffix wildcards (`*.tiktok.com`), and mid-pattern globs (`ads.*.com`) matching extracted TLS SNI, HTTP Host, or DNS QNAME.
  - **Application Protocol Matching**: Matches supported L7 protocols (`TLS`, `HTTP`, `DNS`, `ANY`).
- **Policy Actions & Verdicts**:
  - Actions: `ALLOW`, `BLOCK`, `ALERT`, `LOG`.
  - Configurable `default_action` (default: `ALLOW`).
  - First-match deterministic evaluation sorted ascending by `priority` (lower numeric value = higher precedence), tie-broken by rule `id`.
- **L3/L4 vs L7 Policy Lifecycle**:
  - Provisional L3/L4 evaluation is performed upon flow creation.
  - Final L7 policy evaluation is executed as soon as DPI extracts application metadata (SNI, Host, QNAME), seamlessly overriding provisional default ALLOW decisions with granular L7 domain/app BLOCK rules.
- **Safe JSON Deserialization**:
  - Supports both granular structured rule arrays and categorical ACL sections (`blocked_ips`, `blocked_domains`, `blocked_ports`, `blocked_apps`).
  - Safe error recovery without exceptions or crashes on malformed inputs.
- **Thread-Safety & Dynamic Reloads**:
  - Const-correct rule evaluation with lock-free atomic snapshot swap (`std::shared_ptr<const CompiledRuleSet>`), preparing zero-contention evaluations for Stage 6 worker pipelines.

### Stage 6: Multi-threaded Worker Pipeline [IMPLEMENTED]
- **Architecture**: Ingestion Producer $\rightarrow$ Allocation-free Minimal Routing Parser $\rightarrow$ Canonical Flow Hashing $\rightarrow$ Bounded Worker Queues $\rightarrow$ Fast-Path Dedicated Worker Threads with Isolated `FlowTable`s.
- **Zero-Allocation Routing Parse** (`FlowRouter`): Performs a minimal bounds-checked L2/L3/L4 parse on the producer thread to extract the canonical `FlowKey`, avoiding double parsing while leaving full `ProtocolParser` execution exclusively to worker threads.
- **Strict Flow Affinity & Bidirectional Pinning**:
  - Consistent hashing: `worker_index = FlowKeyHasher()(canonical_key) % num_workers`.
  - Canonical normalization ensures forward and reverse packets produce the exact same 64-bit hash and map deterministically to the identical worker thread.
  - Guarantees strict per-flow in-order packet processing without cross-thread lock contention.
- **Bounded Queues & Backpressure** (`BoundedQueue<PacketJob>`):
  - Thread-safe FIFO queue backed by mutex and condition variables with configurable capacity.
  - Blocks producer on full queues, throttling ingestion to processing throughput.
  - Safe shutdown and drain semantics guarantee zero packet loss on EOF or termination.
- **Zero Mutex Contention Fast-Path**:
  - Each `WorkerThread` owns an isolated, private `FlowTable`.
  - Rule evaluation uses thread-safe lock-free atomic snapshot pointers (`std::shared_ptr<RuleEngine>`).
  - Worker statistics (`alignas(64) WorkerStats`) are cache-line aligned to eliminate false sharing.

### Stage 7: Telemetry, Metrics & Dashboard [PLANNED]
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
