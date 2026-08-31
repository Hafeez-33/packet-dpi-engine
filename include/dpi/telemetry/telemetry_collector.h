#ifndef DPI_TELEMETRY_TELEMETRY_COLLECTOR_H
#define DPI_TELEMETRY_TELEMETRY_COLLECTOR_H

#include "dpi/pipeline/worker_pool.h"
#include "dpi/telemetry/telemetry_types.h"
#include <chrono>
#include <cstddef>
#include <memory>
#include <string>

namespace dpi {

/**
 * @brief Thread-safe telemetry snapshot aggregator and atomic JSON exporter.
 */
class TelemetryCollector {
public:
    explicit TelemetryCollector(const WorkerPool& pool, size_t max_flows = 1000) noexcept;

    void set_status(EngineStatus status) noexcept { status_ = status; }
    EngineStatus status() const noexcept { return status_; }

    /**
     * @brief Captures a consistent point-in-time snapshot from the running worker pool.
     */
    TelemetrySnapshot capture_snapshot() const;

    /**
     * @brief Atomically writes the snapshot JSON to disk via temporary write-and-rename.
     * @param filepath Destination target path for the JSON snapshot file
     * @param pretty Enable pretty indented JSON formatting
     * @return True if write and atomic replacement succeeded, false otherwise
     */
    bool export_json_atomic(const std::string& filepath, bool pretty = true) const;

private:
    const WorkerPool& pool_;
    size_t max_flows_{1000};
    EngineStatus status_{EngineStatus::Running};

    mutable std::chrono::steady_clock::time_point start_time_{};
    mutable std::chrono::steady_clock::time_point last_capture_time_{};
    mutable uint64_t last_packet_count_{0};
    mutable uint64_t last_byte_count_{0};
};

} // namespace dpi

#endif // DPI_TELEMETRY_TELEMETRY_COLLECTOR_H
