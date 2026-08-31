#ifndef DPI_PIPELINE_PIPELINE_TYPES_H
#define DPI_PIPELINE_PIPELINE_TYPES_H

#include "dpi/flow/flow_table.h"
#include "dpi/packet/pcap_types.h"
#include "dpi/threat/threat_config.h"
#include "dpi/risk/risk_config.h"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace dpi {

/**
 * @brief Configuration parameters for the worker thread pipeline.
 */
struct WorkerConfig {
    size_t num_workers{0};                 // 0 = auto-detect hardware concurrency
    size_t queue_capacity{2048};           // Maximum queued packets per worker queue
    FlowTimeoutConfig timeout_config{};    // Configurable flow timeout settings
    ThreatConfig threat_config{};          // Configurable Stage 8 threat detection settings
    RiskConfig risk_config{};              // Configurable Stage 9 risk scoring settings
};

/**
 * @brief Job unit passed through the bounded worker queues.
 * 
 * Takes complete ownership of the PacketRecord payload buffer with zero deep copies.
 */
struct PacketJob {
    PacketRecord record{};
    bool is_nanoseconds{false};
};

/**
 * @brief Plain copyable snapshot of worker statistics for telemetry export and reporting.
 */
struct WorkerStatsSnapshot {
    uint64_t packets_processed{0};
    uint64_t bytes_processed{0};
    uint64_t flows_created{0};
    uint64_t blocked_packets{0};
    uint64_t alert_packets{0};
    uint64_t dpi_classified_flows{0};
    uint64_t malformed_packets{0};
    uint64_t threat_alerts_generated{0};
    uint64_t threat_alerts_dropped{0};
};

/**
 * @brief Per-worker execution statistics aligned to cache-line boundaries (64 bytes)
 * to avoid false sharing. Uses atomic counters so telemetry collectors can safely
 * read snapshot values without data races and without holding locks on the fast path.
 */
struct alignas(64) WorkerStats {
    std::atomic<uint64_t> packets_processed{0};
    std::atomic<uint64_t> bytes_processed{0};
    std::atomic<uint64_t> flows_created{0};
    std::atomic<uint64_t> blocked_packets{0};
    std::atomic<uint64_t> alert_packets{0};
    std::atomic<uint64_t> dpi_classified_flows{0};
    std::atomic<uint64_t> malformed_packets{0};
    std::atomic<uint64_t> threat_alerts_generated{0};
    std::atomic<uint64_t> threat_alerts_dropped{0};

    WorkerStats() = default;

    WorkerStatsSnapshot snapshot() const noexcept {
        return WorkerStatsSnapshot{
            packets_processed.load(std::memory_order_relaxed),
            bytes_processed.load(std::memory_order_relaxed),
            flows_created.load(std::memory_order_relaxed),
            blocked_packets.load(std::memory_order_relaxed),
            alert_packets.load(std::memory_order_relaxed),
            dpi_classified_flows.load(std::memory_order_relaxed),
            malformed_packets.load(std::memory_order_relaxed),
            threat_alerts_generated.load(std::memory_order_relaxed),
            threat_alerts_dropped.load(std::memory_order_relaxed)
        };
    }
};

/**
 * @brief Aggregated pipeline statistics across all worker threads and dispatcher.
 */
struct PipelineStats {
    uint64_t total_packets{0};
    uint64_t total_bytes{0};
    uint64_t total_flows{0};
    uint64_t total_blocked_packets{0};
    uint64_t total_alert_packets{0};
    uint64_t total_dpi_classified_flows{0};
    uint64_t total_malformed_packets{0};
    uint64_t unroutable_packets{0};
    uint64_t total_threat_alerts_generated{0};
    uint64_t total_threat_alerts_dropped{0};
    std::vector<WorkerStatsSnapshot> per_worker_stats{};
};

} // namespace dpi

#endif // DPI_PIPELINE_PIPELINE_TYPES_H
