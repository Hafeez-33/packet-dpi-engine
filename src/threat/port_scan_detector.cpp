#include "dpi/threat/port_scan_detector.h"
#include <sstream>

namespace dpi {

PortScanDetector::PortScanDetector(const PortScanConfig& config) noexcept
    : config_(config) {}

void PortScanDetector::enforce_capacity_limits() {
    if (vertical_trackers_.size() >= config_.max_tracked_sources) {
        // Evict oldest entry
        auto oldest_it = vertical_trackers_.begin();
        uint64_t oldest_time = UINT64_MAX;
        for (auto it = vertical_trackers_.begin(); it != vertical_trackers_.end(); ++it) {
            if (it->second.last_seen_us < oldest_time) {
                oldest_time = it->second.last_seen_us;
                oldest_it = it;
            }
        }
        if (oldest_it != vertical_trackers_.end()) {
            vertical_trackers_.erase(oldest_it);
        }
    }

    if (horizontal_trackers_.size() >= config_.max_tracked_sources) {
        auto oldest_it = horizontal_trackers_.begin();
        uint64_t oldest_time = UINT64_MAX;
        for (auto it = horizontal_trackers_.begin(); it != horizontal_trackers_.end(); ++it) {
            if (it->second.last_seen_us < oldest_time) {
                oldest_time = it->second.last_seen_us;
                oldest_it = it;
            }
        }
        if (oldest_it != horizontal_trackers_.end()) {
            horizontal_trackers_.erase(oldest_it);
        }
    }
}

bool PortScanDetector::check_packet(const ParsedPacket& packet, uint64_t timestamp_us, SecurityAlert& out_alert) {
    if (!packet.is_valid()) {
        return false;
    }

    IPAddress src_ip = packet.is_ipv4() ? IPAddress(packet.ipv4.src_ip) : (packet.is_ipv6() ? IPAddress(packet.ipv6.src_ip) : IPAddress{});
    IPAddress dst_ip = packet.is_ipv4() ? IPAddress(packet.ipv4.dst_ip) : (packet.is_ipv6() ? IPAddress(packet.ipv6.dst_ip) : IPAddress{});
    uint16_t src_port = packet.is_tcp() ? packet.tcp.src_port : (packet.is_udp() ? packet.udp.src_port : 0);
    uint16_t dst_port = packet.is_tcp() ? packet.tcp.dst_port : (packet.is_udp() ? packet.udp.dst_port : 0);

    if (!src_ip.is_valid() || !dst_ip.is_valid() || dst_port == 0) {
        return false;
    }

    // --- 1. Check Vertical Port Scan (Single Src -> Single Dst -> Many Ports) ---
    enforce_capacity_limits();
    auto& v_tracker = vertical_trackers_[src_ip];
    if (v_tracker.window_start_us == 0 || (timestamp_us > v_tracker.window_start_us && timestamp_us - v_tracker.window_start_us > config_.window_us)) {
        v_tracker.window_start_us = timestamp_us;
        v_tracker.host_to_ports.clear();
        v_tracker.alert_emitted = false;
    }
    v_tracker.last_seen_us = timestamp_us;

    auto& ports_set = v_tracker.host_to_ports[dst_ip];
    ports_set.insert(dst_port);

    if (!v_tracker.alert_emitted && ports_set.size() >= config_.vertical_port_threshold) {
        v_tracker.alert_emitted = true;
        out_alert.timestamp_us = timestamp_us;
        out_alert.severity = AlertSeverity::High;
        out_alert.category = ThreatCategory::PortScan;
        out_alert.signature_name = "Vertical Port Scan Detected";
        out_alert.description = "Source IP targeted " + std::to_string(ports_set.size()) + " distinct ports on host " + dst_ip.to_string();
        out_alert.src_ip = src_ip;
        out_alert.dst_ip = dst_ip;
        out_alert.src_port = src_port;
        out_alert.dst_port = dst_port;
        out_alert.transport = packet.l4_type;
        out_alert.trigger_reason = "Vertical scan threshold exceeded: " + std::to_string(ports_set.size()) + " ports probed within " + std::to_string(config_.window_us / 1000) + " ms window";
        return true;
    }

    // --- 2. Check Horizontal Port Scan (Single Src -> Many Dsts -> Single Port) ---
    auto& h_tracker = horizontal_trackers_[src_ip];
    if (h_tracker.window_start_us == 0 || (timestamp_us > h_tracker.window_start_us && timestamp_us - h_tracker.window_start_us > config_.window_us)) {
        h_tracker.window_start_us = timestamp_us;
        h_tracker.port_to_hosts.clear();
        h_tracker.alert_emitted = false;
    }
    h_tracker.last_seen_us = timestamp_us;

    auto& hosts_set = h_tracker.port_to_hosts[dst_port];
    hosts_set.insert(dst_ip);

    if (!h_tracker.alert_emitted && hosts_set.size() >= config_.horizontal_host_threshold) {
        h_tracker.alert_emitted = true;
        out_alert.timestamp_us = timestamp_us;
        out_alert.severity = AlertSeverity::High;
        out_alert.category = ThreatCategory::PortScan;
        out_alert.signature_name = "Horizontal Port Scan (Host Sweep) Detected";
        out_alert.description = "Source IP swept " + std::to_string(hosts_set.size()) + " distinct destination hosts on port " + std::to_string(dst_port);
        out_alert.src_ip = src_ip;
        out_alert.dst_ip = dst_ip;
        out_alert.src_port = src_port;
        out_alert.dst_port = dst_port;
        out_alert.transport = packet.l4_type;
        out_alert.trigger_reason = "Horizontal scan threshold exceeded: " + std::to_string(hosts_set.size()) + " hosts probed on port " + std::to_string(dst_port) + " within " + std::to_string(config_.window_us / 1000) + " ms window";
        return true;
    }

    return false;
}

void PortScanDetector::cleanup_expired(uint64_t current_time_us) {
    for (auto it = vertical_trackers_.begin(); it != vertical_trackers_.end(); ) {
        if (current_time_us > it->second.last_seen_us && current_time_us - it->second.last_seen_us > config_.window_us * 2) {
            it = vertical_trackers_.erase(it);
        } else {
            ++it;
        }
    }

    for (auto it = horizontal_trackers_.begin(); it != horizontal_trackers_.end(); ) {
        if (current_time_us > it->second.last_seen_us && current_time_us - it->second.last_seen_us > config_.window_us * 2) {
            it = horizontal_trackers_.erase(it);
        } else {
            ++it;
        }
    }
}

void PortScanDetector::reset() {
    vertical_trackers_.clear();
    horizontal_trackers_.clear();
}

} // namespace dpi
