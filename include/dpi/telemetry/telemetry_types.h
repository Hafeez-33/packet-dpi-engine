#ifndef DPI_TELEMETRY_TELEMETRY_TYPES_H
#define DPI_TELEMETRY_TELEMETRY_TYPES_H

#include "dpi/pipeline/pipeline_types.h"
#include "dpi/threat/threat_types.h"
#include <cstdint>
#include <string>
#include <vector>

namespace dpi {

/**
 * @brief Current operational state of the packet inspection engine.
 */
enum class EngineStatus {
    NoTelemetry = 0,
    Running,
    Completed,
    Error
};

std::string_view engine_status_to_string(EngineStatus status) noexcept;

/**
 * @brief Summary telemetry record for an individual tracked flow.
 * 
 * Contains only compact metadata and counters with zero packet payload copies.
 */
struct FlowTelemetry {
    std::string flow_id{};
    std::string src_ip{};
    std::string dst_ip{};
    uint16_t src_port{0};
    uint16_t dst_port{0};
    std::string transport_protocol{};
    std::string app_protocol{"Unknown"};
    std::string host_or_sni{};
    std::string tcp_state{"N/A"};
    std::string policy_verdict{"ALLOW"};
    std::string matched_rule_name{};
    uint64_t packets_forward{0};
    uint64_t packets_reverse{0};
    uint64_t bytes_forward{0};
    uint64_t bytes_reverse{0};
    uint64_t duration_ms{0};
    bool is_blocked{false};
};

/**
 * @brief Consistent point-in-time telemetry snapshot gathered from all workers and pipeline state.
 */
struct TelemetrySnapshot {
    EngineStatus status{EngineStatus::Running};
    uint64_t timestamp_ns{0};
    double duration_sec{0.0};

    // Global Ingestion & Throughput Metrics
    uint64_t total_packets{0};
    uint64_t total_bytes{0};
    double packets_per_sec{0.0};
    double bytes_per_sec{0.0};

    // Flow State Metrics
    uint64_t total_flows{0};
    uint64_t active_flows{0};
    uint64_t completed_flows{0};

    // Protocol Breakdown (L4)
    uint64_t tcp_flows{0};
    uint64_t udp_flows{0};
    uint64_t other_l4_flows{0};

    // Application Protocol Breakdown (L7)
    uint64_t tls_flows{0};
    uint64_t http_flows{0};
    uint64_t dns_flows{0};
    uint64_t unknown_l7_flows{0};

    // Policy & Firewall Verdicts
    uint64_t blocked_packets{0};
    uint64_t alert_packets{0};
    uint64_t blocked_flows{0};
    uint64_t allowed_flows{0};

    // Error & Anomaly Metrics
    uint64_t malformed_packets{0};
    uint64_t unroutable_packets{0};

    // Stage 8 Threat & Anomaly Metrics
    ThreatStatsSnapshot threat_stats{};

    // Worker Pipeline Telemetry
    std::vector<WorkerStatsSnapshot> worker_stats{};
    std::vector<size_t> worker_queue_sizes{};

    // Bounded Flow Telemetry Sample
    std::vector<FlowTelemetry> flows{};

    // Bounded Threat Alerts Sample
    std::vector<SecurityAlert> alerts{};

    /**
     * @brief Serializes the telemetry snapshot to a valid, clean JSON string.
     */
    std::string to_json(bool pretty = true) const;
};

} // namespace dpi

#endif // DPI_TELEMETRY_TELEMETRY_TYPES_H
