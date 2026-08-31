#include "dpi/threat/syn_flood_detector.h"
#include <string>

namespace dpi {

SynFloodDetector::SynFloodDetector(const SynFloodConfig& config) noexcept
    : config_(config) {}

void SynFloodDetector::enforce_capacity_limits() {
    if (sources_.size() >= config_.max_tracked_sources) {
        auto oldest_it = sources_.begin();
        uint64_t oldest_time = UINT64_MAX;
        for (auto it = sources_.begin(); it != sources_.end(); ++it) {
            if (it->second.last_seen_us < oldest_time) {
                oldest_time = it->second.last_seen_us;
                oldest_it = it;
            }
        }
        if (oldest_it != sources_.end()) {
            sources_.erase(oldest_it);
        }
    }
}

bool SynFloodDetector::check_packet(const ParsedPacket& packet, uint64_t timestamp_us, SecurityAlert& out_alert) {
    if (!packet.is_valid() || !packet.is_tcp()) {
        return false;
    }

    const auto& tcp = packet.tcp;
    IPAddress src_ip = packet.is_ipv4() ? IPAddress(packet.ipv4.src_ip) : (packet.is_ipv6() ? IPAddress(packet.ipv6.src_ip) : IPAddress{});
    IPAddress dst_ip = packet.is_ipv4() ? IPAddress(packet.ipv4.dst_ip) : (packet.is_ipv6() ? IPAddress(packet.ipv6.dst_ip) : IPAddress{});
    uint16_t src_port = tcp.src_port;
    uint16_t dst_port = tcp.dst_port;

    if (!src_ip.is_valid() || !dst_ip.is_valid()) {
        return false;
    }

    // Handle handshake completion or teardown in reverse direction:
    // If incoming packet is from responder (e.g. SYN-ACK or ACK from dst), or ACK from initiator
    HalfOpenKey fwd_key{dst_ip, src_port, dst_port};
    HalfOpenKey rev_key{src_ip, dst_port, src_port};

    if (tcp.flags.ack || tcp.flags.rst || tcp.flags.fin) {
        // Check if responder or initiator is completing a tracked connection
        auto rev_it = sources_.find(dst_ip);
        if (rev_it != sources_.end()) {
            if (rev_it->second.half_open_conns.erase(rev_key) > 0) {
                rev_it->second.completed_handshakes++;
            }
        }

        auto fwd_it = sources_.find(src_ip);
        if (fwd_it != sources_.end()) {
            if (fwd_it->second.half_open_conns.erase(fwd_key) > 0) {
                fwd_it->second.completed_handshakes++;
            }
        }
    }

    // Process SYN from initiator (SYN=1, ACK=0)
    if (tcp.flags.syn && !tcp.flags.ack) {
        enforce_capacity_limits();
        auto& tracker = sources_[src_ip];

        if (tracker.window_start_us == 0 || (timestamp_us > tracker.window_start_us && timestamp_us - tracker.window_start_us > config_.window_us)) {
            tracker.window_start_us = timestamp_us;
            tracker.syn_attempts = 0;
            tracker.completed_handshakes = 0;
            tracker.alert_emitted = false;
        }

        tracker.last_seen_us = timestamp_us;
        tracker.syn_attempts++;
        tracker.half_open_conns[fwd_key] = timestamp_us;

        // Cleanup expired half-opens for this source
        for (auto it = tracker.half_open_conns.begin(); it != tracker.half_open_conns.end(); ) {
            if (timestamp_us > it->second && timestamp_us - it->second > config_.half_open_timeout_us) {
                it = tracker.half_open_conns.erase(it);
            } else {
                ++it;
            }
        }

        size_t active_half_opens = tracker.half_open_conns.size();

        // Evaluation criteria: high half-open accumulation or uncompleted burst rate
        bool half_open_alert = (active_half_opens >= config_.half_open_threshold);
        bool burst_alert = (tracker.syn_attempts >= config_.syn_rate_threshold && tracker.completed_handshakes == 0);

        if (!tracker.alert_emitted && (half_open_alert || burst_alert)) {
            tracker.alert_emitted = true;
            out_alert.timestamp_us = timestamp_us;
            out_alert.severity = AlertSeverity::Critical;
            out_alert.category = ThreatCategory::SynFlood;
            out_alert.signature_name = "TCP SYN Flood / Connection DoS Detected";
            out_alert.description = "Source IP accumulated " + std::to_string(active_half_opens) + " unacknowledged half-open TCP connections (" + std::to_string(tracker.syn_attempts) + " SYNs sent)";
            out_alert.src_ip = src_ip;
            out_alert.dst_ip = dst_ip;
            out_alert.src_port = src_port;
            out_alert.dst_port = dst_port;
            out_alert.transport = L4Type::TCP;
            out_alert.trigger_reason = "SYN Flood threshold exceeded: " + std::to_string(active_half_opens) + " half-open connections (threshold=" + std::to_string(config_.half_open_threshold) + ") within " + std::to_string(config_.window_us / 1000) + " ms";
            return true;
        }
    }

    return false;
}

void SynFloodDetector::cleanup_expired(uint64_t current_time_us) {
    for (auto it = sources_.begin(); it != sources_.end(); ) {
        if (current_time_us > it->second.last_seen_us && current_time_us - it->second.last_seen_us > config_.half_open_timeout_us * 2) {
            it = sources_.erase(it);
        } else {
            // Clean up individual expired half-opens
            for (auto hit = it->second.half_open_conns.begin(); hit != it->second.half_open_conns.end(); ) {
                if (current_time_us > hit->second && current_time_us - hit->second > config_.half_open_timeout_us) {
                    hit = it->second.half_open_conns.erase(hit);
                } else {
                    ++hit;
                }
            }
            ++it;
        }
    }
}

void SynFloodDetector::reset() {
    sources_.clear();
}

} // namespace dpi
