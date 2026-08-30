#ifndef DPI_PIPELINE_PIPELINE_TYPES_H
#define DPI_PIPELINE_PIPELINE_TYPES_H

#include "dpi/flow/flow_table.h"
#include "dpi/packet/pcap_types.h"
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
 * @brief Per-worker execution statistics aligned to cache-line boundaries (64 bytes)
 * to avoid false sharing between concurrent worker cores.
 */
struct alignas(64) WorkerStats {
    uint64_t packets_processed{0};
    uint64_t bytes_processed{0};
    uint64_t flows_created{0};
    uint64_t blocked_packets{0};
    uint64_t alert_packets{0};
    uint64_t dpi_classified_flows{0};
    uint64_t malformed_packets{0};
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
    std::vector<WorkerStats> per_worker_stats{};
};

} // namespace dpi

#endif // DPI_PIPELINE_PIPELINE_TYPES_H
