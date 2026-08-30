#include "dpi/telemetry/telemetry_collector.h"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>

namespace dpi {

TelemetryCollector::TelemetryCollector(const WorkerPool& pool, size_t max_flows) noexcept
    : pool_(pool),
      max_flows_(max_flows > 0 ? max_flows : 1000),
      start_time_(std::chrono::steady_clock::now()),
      last_capture_time_(start_time_) {}

TelemetrySnapshot TelemetryCollector::capture_snapshot() const {
    auto now = std::chrono::steady_clock::now();
    TelemetrySnapshot snap{};
    snap.status = status_;
    snap.timestamp_ns = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count());
    snap.duration_sec = std::chrono::duration<double>(now - start_time_).count();

    const auto& workers = pool_.workers();
    snap.worker_stats.reserve(workers.size());
    snap.worker_queue_sizes.reserve(workers.size());

    // Aggregate worker stats atomically
    for (const auto& w : workers) {
        auto ws = w->stats().snapshot();
        snap.total_packets += ws.packets_processed;
        snap.total_bytes += ws.bytes_processed;
        snap.total_flows += ws.flows_created;
        snap.blocked_packets += ws.blocked_packets;
        snap.alert_packets += ws.alert_packets;
        snap.malformed_packets += ws.malformed_packets;

        snap.worker_stats.push_back(ws);
        snap.worker_queue_sizes.push_back(w->queue_size());
    }

    // Instantaneous or average throughput
    double delta_sec = std::chrono::duration<double>(now - last_capture_time_).count();
    if (delta_sec > 0.001) {
        uint64_t d_packets = (snap.total_packets >= last_packet_count_) ? (snap.total_packets - last_packet_count_) : 0;
        uint64_t d_bytes = (snap.total_bytes >= last_byte_count_) ? (snap.total_bytes - last_byte_count_) : 0;
        snap.packets_per_sec = static_cast<double>(d_packets) / delta_sec;
        snap.bytes_per_sec = static_cast<double>(d_bytes) / delta_sec;
    } else if (snap.duration_sec > 0.001) {
        snap.packets_per_sec = static_cast<double>(snap.total_packets) / snap.duration_sec;
        snap.bytes_per_sec = static_cast<double>(snap.total_bytes) / snap.duration_sec;
    }

    last_capture_time_ = now;
    last_packet_count_ = snap.total_packets;
    last_byte_count_ = snap.total_bytes;

    // Collect bounded flow records across worker FlowTables
    size_t flows_collected = 0;
    for (const auto& w : workers) {
        w->flow_table().for_each_flow([&](const std::shared_ptr<FlowEntry>& f) {
            if (flows_collected >= max_flows_) return;

            FlowTelemetry ft{};
            ft.flow_id = f->key().to_string();
            ft.src_ip = f->key().src.ip.to_string();
            ft.dst_ip = f->key().dst.ip.to_string();
            ft.src_port = f->key().src.port;
            ft.dst_port = f->key().dst.port;
            ft.transport_protocol = (f->key().protocol == ipproto::TCP) ? "TCP" :
                                   ((f->key().protocol == ipproto::UDP) ? "UDP" : "Other");

            if (f->is_classified()) {
                switch (f->l7_metadata().protocol) {
                    case AppProtocol::TLS: ft.app_protocol = "TLS"; snap.tls_flows++; break;
                    case AppProtocol::HTTP: ft.app_protocol = "HTTP"; snap.http_flows++; break;
                    case AppProtocol::DNS: ft.app_protocol = "DNS"; snap.dns_flows++; break;
                    default: ft.app_protocol = "Unknown"; snap.unknown_l7_flows++; break;
                }
            } else {
                ft.app_protocol = "Unknown";
                snap.unknown_l7_flows++;
            }

            ft.host_or_sni = f->l7_metadata().hostname;
            ft.tcp_state = (f->key().protocol == ipproto::TCP) ? std::string(tcp_state_to_string(f->tcp_state_machine().state())) : "UDP";
            ft.policy_verdict = std::string(rule_action_to_string(f->policy_verdict().action));
            ft.matched_rule_name = f->policy_verdict().matched_rule_name;
            ft.is_blocked = f->is_blocked();

            if (f->is_blocked()) snap.blocked_flows++;
            else snap.allowed_flows++;

            ft.packets_forward = f->stats().forward.packets;
            ft.packets_reverse = f->stats().reverse.packets;
            ft.bytes_forward = f->stats().forward.bytes;
            ft.bytes_reverse = f->stats().reverse.bytes;
            ft.duration_ms = f->stats().duration_us() / 1000;

            if (f->key().protocol == ipproto::TCP) snap.tcp_flows++;
            else if (f->key().protocol == ipproto::UDP) snap.udp_flows++;
            else snap.other_l4_flows++;

            if (f->state() != FlowState::Closed && f->state() != FlowState::Expired) {
                snap.active_flows++;
            } else {
                snap.completed_flows++;
            }

            snap.flows.push_back(std::move(ft));
            flows_collected++;
        });
    }

    return snap;
}

bool TelemetryCollector::export_json_atomic(const std::string& filepath, bool pretty) const {
    if (filepath.empty()) return false;

    TelemetrySnapshot snap = capture_snapshot();
    std::string json_str = snap.to_json(pretty);

    std::string temp_filepath = filepath + ".tmp";
    {
        std::ofstream ofs(temp_filepath, std::ios::out | std::ios::trunc);
        if (!ofs.is_open()) {
            return false;
        }
        ofs << json_str;
        ofs.flush();
        if (ofs.fail()) {
            return false;
        }
    }

    // Atomic replacement
    std::error_code ec;
    std::filesystem::copy_file(temp_filepath, filepath,
                               std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) {
        return false;
    }
    std::filesystem::remove(temp_filepath, ec);
    return true;
}

} // namespace dpi
