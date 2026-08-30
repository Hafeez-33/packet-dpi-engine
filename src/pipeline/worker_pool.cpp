#include "dpi/pipeline/worker_pool.h"
#include "dpi/pipeline/flow_router.h"
#include <algorithm>
#include <thread>

namespace dpi {

WorkerPool::WorkerPool(const WorkerConfig& config,
                       std::shared_ptr<RuleEngine> rule_engine) noexcept
    : config_(config), rule_engine_(std::move(rule_engine)) {
    size_t count = config_.num_workers;
    if (count == 0) {
        count = std::max<size_t>(1, std::thread::hardware_concurrency());
    }

    workers_.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        workers_.push_back(std::make_unique<WorkerThread>(
            i, config_.queue_capacity, config_.timeout_config, rule_engine_));
    }
}

WorkerPool::~WorkerPool() {
    stop();
}

void WorkerPool::start() {
    if (!running_.exchange(true)) {
        for (auto& worker : workers_) {
            worker->start();
        }
    }
}

void WorkerPool::stop() {
    if (running_.exchange(false)) {
        for (auto& worker : workers_) {
            worker->request_stop();
        }
        for (auto& worker : workers_) {
            worker->join();
        }
    }
}

bool WorkerPool::dispatch(PacketRecord record, bool is_nanoseconds) {
    if (!running_) {
        return false;
    }

    FlowKey key;
    bool routable = FlowRouter::extract_flow_key(record.payload.data(), record.payload.size(), key);

    size_t target_worker = 0;
    if (routable) {
        target_worker = FlowKeyHasher()(key) % workers_.size();
    } else {
        // Deterministic routing fallback for unroutable / malformed / non-IP packets
        unroutable_count_++;
        target_worker = 0;
    }

    return workers_[target_worker]->enqueue(PacketJob{std::move(record), is_nanoseconds});
}

PipelineStats WorkerPool::process_pcap(PcapReader& reader) {
    // 1. Start worker threads if not running
    start();

    // 2. Read packets sequentially from PcapReader
    PacketRecord record;
    bool is_nanoseconds = reader.global_header().is_nanosecond_resolution;

    // 3. Dispatch every packet until EOF or stream error
    while (reader.read_next_packet(record) == PcapErrorCode::Success) {
        dispatch(std::move(record), is_nanoseconds);
    }

    // 4. Stop workers and drain remaining jobs in FIFO order
    stop();

    // 5. Aggregate final statistics
    return get_aggregated_stats();
}

PipelineStats WorkerPool::get_aggregated_stats() const noexcept {
    PipelineStats total{};
    total.unroutable_packets = unroutable_count_.load();
    total.per_worker_stats.reserve(workers_.size());

    for (const auto& worker : workers_) {
        const auto& ws = worker->stats();
        total.total_packets += ws.packets_processed;
        total.total_bytes += ws.bytes_processed;
        total.total_flows += ws.flows_created;
        total.total_blocked_packets += ws.blocked_packets;
        total.total_alert_packets += ws.alert_packets;
        total.total_dpi_classified_flows += ws.dpi_classified_flows;
        total.total_malformed_packets += ws.malformed_packets;
        total.per_worker_stats.push_back(ws);
    }

    return total;
}

} // namespace dpi
