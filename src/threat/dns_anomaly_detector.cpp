#include "dpi/threat/dns_anomaly_detector.h"
#include "dpi/threat/entropy_calculator.h"
#include <iomanip>
#include <sstream>

namespace dpi {

DnsAnomalyDetector::DnsAnomalyDetector(const DnsAnomalyConfig& config) noexcept
    : config_(config) {}

bool DnsAnomalyDetector::check_dns_query(std::string_view qname,
                                         const ParsedPacket& packet,
                                         uint64_t timestamp_us,
                                         SecurityAlert& out_alert) const {
    if (qname.empty()) {
        return false;
    }

    IPAddress src_ip = packet.is_ipv4() ? IPAddress(packet.ipv4.src_ip) : (packet.is_ipv6() ? IPAddress(packet.ipv6.src_ip) : IPAddress{});
    IPAddress dst_ip = packet.is_ipv4() ? IPAddress(packet.ipv4.dst_ip) : (packet.is_ipv6() ? IPAddress(packet.ipv6.dst_ip) : IPAddress{});
    uint16_t src_port = packet.is_tcp() ? packet.tcp.src_port : (packet.is_udp() ? packet.udp.src_port : 0);
    uint16_t dst_port = packet.is_tcp() ? packet.tcp.dst_port : (packet.is_udp() ? packet.udp.dst_port : 0);
    L4Type transport = packet.l4_type;

    // 1. Structural Checks: FQDN Length
    if (qname.size() > config_.max_fqdn_length) {
        out_alert.timestamp_us = timestamp_us;
        out_alert.severity = AlertSeverity::Medium;
        out_alert.category = ThreatCategory::DnsTunneling;
        out_alert.signature_name = "DNS Abnormally Long FQDN Query";
        out_alert.description = "Queried DNS domain length (" + std::to_string(qname.size()) + " chars) exceeds threshold";
        out_alert.src_ip = src_ip;
        out_alert.dst_ip = dst_ip;
        out_alert.src_port = src_port;
        out_alert.dst_port = dst_port;
        out_alert.transport = transport;
        out_alert.app_protocol = AppProtocol::DNS;
        out_alert.matched_snippet = std::string(qname.substr(0, 128));
        out_alert.trigger_reason = "Heuristic length check: FQDN length=" + std::to_string(qname.size()) + " (threshold=" + std::to_string(config_.max_fqdn_length) + ")";
        return true;
    }

    // 2. Parse individual labels to check label length, depth, and entropy
    size_t label_count = 0;
    size_t start = 0;
    size_t max_label_len = 0;
    std::string_view longest_label{};

    for (size_t i = 0; i <= qname.size(); ++i) {
        if (i == qname.size() || qname[i] == '.') {
            if (i > start) {
                std::string_view label = qname.substr(start, i - start);
                label_count++;
                if (label.size() > max_label_len) {
                    max_label_len = label.size();
                    longest_label = label;
                }
            }
            start = i + 1;
        }
    }

    // Check individual label length
    if (max_label_len > config_.max_label_length) {
        out_alert.timestamp_us = timestamp_us;
        out_alert.severity = AlertSeverity::Medium;
        out_alert.category = ThreatCategory::DnsTunneling;
        out_alert.signature_name = "DNS Abnormally Long Subdomain Label";
        out_alert.description = "DNS label length (" + std::to_string(max_label_len) + " chars) indicates potential tunnel encapsulation";
        out_alert.src_ip = src_ip;
        out_alert.dst_ip = dst_ip;
        out_alert.src_port = src_port;
        out_alert.dst_port = dst_port;
        out_alert.transport = transport;
        out_alert.app_protocol = AppProtocol::DNS;
        out_alert.matched_snippet = std::string(longest_label.substr(0, 128));
        out_alert.trigger_reason = "Heuristic label check: Subdomain label length=" + std::to_string(max_label_len) + " (threshold=" + std::to_string(config_.max_label_length) + ")";
        return true;
    }

    // 3. Statistical Check: Shannon Entropy (only on domains with sufficient length >= 12)
    if (qname.size() >= 12) {
        double entropy = EntropyCalculator::calculate_shannon_entropy(qname);
        if (entropy >= config_.max_entropy_threshold) {
            std::ostringstream ss;
            ss << std::fixed << std::setprecision(3) << entropy;

            out_alert.timestamp_us = timestamp_us;
            out_alert.severity = AlertSeverity::High;
            out_alert.category = ThreatCategory::DnsDgaAnomaly;
            out_alert.signature_name = "High-Entropy DNS Query (Potential DGA / Tunneling Heuristic)";
            out_alert.description = "Domain name exhibits abnormally high Shannon entropy (" + ss.str() + " bits/char)";
            out_alert.src_ip = src_ip;
            out_alert.dst_ip = dst_ip;
            out_alert.src_port = src_port;
            out_alert.dst_port = dst_port;
            out_alert.transport = transport;
            out_alert.app_protocol = AppProtocol::DNS;
            out_alert.matched_snippet = std::string(qname.substr(0, 128));
            out_alert.trigger_reason = "Heuristic entropy score=" + ss.str() + " bits/char (threshold=" + std::to_string(config_.max_entropy_threshold).substr(0, 4) + ") on FQDN=" + std::string(qname);
            return true;
        }
    }

    // 4. Subdomain nesting depth check
    if (label_count > config_.max_subdomain_depth + 2) { // +2 accounts for second-level domain + TLD
        out_alert.timestamp_us = timestamp_us;
        out_alert.severity = AlertSeverity::Low;
        out_alert.category = ThreatCategory::DnsTunneling;
        out_alert.signature_name = "Deeply Nested DNS Subdomain Query";
        out_alert.description = "Query contains " + std::to_string(label_count) + " dot-delimited subdomain levels";
        out_alert.src_ip = src_ip;
        out_alert.dst_ip = dst_ip;
        out_alert.src_port = src_port;
        out_alert.dst_port = dst_port;
        out_alert.transport = transport;
        out_alert.app_protocol = AppProtocol::DNS;
        out_alert.matched_snippet = std::string(qname.substr(0, 128));
        out_alert.trigger_reason = "Heuristic nesting check: Label count=" + std::to_string(label_count) + " (threshold=" + std::to_string(config_.max_subdomain_depth + 2) + ")";
        return true;
    }

    return false;
}

} // namespace dpi
