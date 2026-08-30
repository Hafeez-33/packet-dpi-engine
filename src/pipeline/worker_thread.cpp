#include "dpi/pipeline/worker_thread.h"
#include <utility>

namespace dpi {

WorkerThread::WorkerThread(size_t id,
                           size_t queue_capacity,
                           const FlowTimeoutConfig& timeout_config,
                           std::shared_ptr<RuleEngine> rule_engine) noexcept
    : id_(id),
      queue_(queue_capacity),
      rule_engine_(std::move(rule_engine)) {
    flow_table_.set_timeout_config(timeout_config);
    if (rule_engine_) {
        flow_table_.set_rule_engine(rule_engine_);
    }
}

WorkerThread::~WorkerThread() {
    request_stop();
    join();
}

void WorkerThread::start() {
    if (!running_.exchange(true)) {
        thread_ = std::thread(&WorkerThread::run, this);
    }
}

bool WorkerThread::enqueue(PacketJob job) {
    return queue_.push(std::move(job));
}

void WorkerThread::request_stop() noexcept {
    queue_.shutdown();
}

void WorkerThread::join() {
    if (thread_.joinable()) {
        thread_.join();
    }
    running_ = false;
}

void WorkerThread::run() {
    PacketJob job;

    while (queue_.pop(job)) {
        // Execute full bounds-checked protocol parsing worker-locally
        ParsedPacket parsed = ProtocolParser::parse(job.record);
        if (!parsed.is_valid()) {
            stats_.malformed_packets.fetch_add(1, std::memory_order_relaxed);
            continue;
        }

        size_t prev_flow_count = flow_table_.size();
        auto flow = flow_table_.process_packet(job.record, parsed, job.is_nanoseconds);

        if (flow != nullptr) {
            stats_.packets_processed.fetch_add(1, std::memory_order_relaxed);
            size_t wire_len = (job.record.header.orig_len > 0) ? job.record.header.orig_len : job.record.payload.size();
            stats_.bytes_processed.fetch_add(wire_len, std::memory_order_relaxed);

            if (flow_table_.size() > prev_flow_count) {
                stats_.flows_created.fetch_add(1, std::memory_order_relaxed);
            }

            if (flow->is_blocked()) {
                stats_.blocked_packets.fetch_add(1, std::memory_order_relaxed);
            } else if (flow->policy_verdict().action == RuleAction::Alert) {
                stats_.alert_packets.fetch_add(1, std::memory_order_relaxed);
            }
        } else {
            stats_.malformed_packets.fetch_add(1, std::memory_order_relaxed);
        }
    }

    // Count classified flows upon completion
    uint64_t classified_count = 0;
    flow_table_.for_each_flow([&classified_count](const std::shared_ptr<FlowEntry>& f) {
        if (f->is_classified()) {
            classified_count++;
        }
    });
    stats_.dpi_classified_flows.store(classified_count, std::memory_order_relaxed);
}

} // namespace dpi
