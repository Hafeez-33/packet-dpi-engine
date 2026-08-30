#ifndef DPI_PIPELINE_WORKER_THREAD_H
#define DPI_PIPELINE_WORKER_THREAD_H

#include "dpi/flow/flow_table.h"
#include "dpi/pipeline/bounded_queue.h"
#include "dpi/pipeline/pipeline_types.h"
#include "dpi/protocols/protocol_parser.h"
#include "dpi/rules/rule_engine.h"
#include <atomic>
#include <memory>
#include <thread>

namespace dpi {

/**
 * @brief Dedicated worker thread executing full protocol parsing, isolated flow tracking,
 * DPI inspection, and policy evaluation.
 */
class WorkerThread {
public:
    WorkerThread(size_t id,
                 size_t queue_capacity,
                 const FlowTimeoutConfig& timeout_config,
                 std::shared_ptr<RuleEngine> rule_engine) noexcept;

    ~WorkerThread();

    // Non-copyable, non-movable
    WorkerThread(const WorkerThread&) = delete;
    WorkerThread& operator=(const WorkerThread&) = delete;

    void start();
    bool enqueue(PacketJob job);
    void request_stop() noexcept;
    void join();

    size_t id() const noexcept { return id_; }
    size_t queue_size() const noexcept { return queue_.size(); }
    const WorkerStats& stats() const noexcept { return stats_; }
    const FlowTable& flow_table() const noexcept { return flow_table_; }

private:
    void run();

    size_t id_{0};
    BoundedQueue<PacketJob> queue_;
    FlowTable flow_table_{};
    std::shared_ptr<RuleEngine> rule_engine_{nullptr};
    WorkerStats stats_{};

    std::thread thread_{};
    std::atomic<bool> running_{false};
};

} // namespace dpi

#endif // DPI_PIPELINE_WORKER_THREAD_H
