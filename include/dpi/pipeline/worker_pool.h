#ifndef DPI_PIPELINE_WORKER_POOL_H
#define DPI_PIPELINE_WORKER_POOL_H

#include "dpi/packet/pcap_reader.h"
#include "dpi/pipeline/pipeline_types.h"
#include "dpi/pipeline/worker_thread.h"
#include "dpi/rules/rule_engine.h"
#include <atomic>
#include <memory>
#include <vector>

namespace dpi {

/**
 * @brief High-performance multi-worker packet processing orchestrator with canonical flow affinity.
 */
class WorkerPool {
public:
    explicit WorkerPool(const WorkerConfig& config = {},
                        std::shared_ptr<RuleEngine> rule_engine = nullptr) noexcept;

    ~WorkerPool();

    // Non-copyable, non-movable
    WorkerPool(const WorkerPool&) = delete;
    WorkerPool& operator=(const WorkerPool&) = delete;

    /**
     * @brief Starts all worker threads.
     */
    void start();

    /**
     * @brief Signals workers to drain remaining jobs, terminates threads, and joins.
     */
    void stop();

    /**
     * @brief Dispatches a raw packet record to the appropriate worker via canonical flow affinity.
     * @param record Raw packet record
     * @param is_nanoseconds Timestamp resolution flag
     * @return True if enqueued successfully, false if pool is stopped
     */
    bool dispatch(PacketRecord record, bool is_nanoseconds = false);

    /**
     * @brief Processes an entire PCAP reader stream through the worker pipeline and returns aggregated stats.
     */
    PipelineStats process_pcap(PcapReader& reader);

    /**
     * @brief Aggregates current statistics across all worker threads.
     */
    PipelineStats get_aggregated_stats() const noexcept;

    size_t worker_count() const noexcept { return workers_.size(); }
    bool is_running() const noexcept { return running_; }

private:
    WorkerConfig config_{};
    std::shared_ptr<RuleEngine> rule_engine_{nullptr};
    std::vector<std::unique_ptr<WorkerThread>> workers_{};
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> unroutable_count_{0};
};

} // namespace dpi

#endif // DPI_PIPELINE_WORKER_POOL_H
