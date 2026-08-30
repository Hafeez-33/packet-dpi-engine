#include "dpi/telemetry/telemetry_types.h"
#include <iomanip>
#include <sstream>

namespace dpi {

std::string_view engine_status_to_string(EngineStatus status) noexcept {
    switch (status) {
        case EngineStatus::Running:
            return "ENGINE_RUNNING";
        case EngineStatus::Completed:
            return "ENGINE_COMPLETED";
        case EngineStatus::Error:
            return "ENGINE_ERROR";
        case EngineStatus::NoTelemetry:
        default:
            return "NO_TELEMETRY";
    }
}

static std::string escape_json(const std::string& str) {
    std::ostringstream o;
    for (char c : str) {
        switch (c) {
            case '"': o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\b': o << "\\b"; break;
            case '\f': o << "\\f"; break;
            case '\n': o << "\\n"; break;
            case '\r': o << "\\r"; break;
            case '\t': o << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) <= 0x1f) {
                    o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
                } else {
                    o << c;
                }
        }
    }
    return o.str();
}

std::string TelemetrySnapshot::to_json(bool pretty) const {
    std::ostringstream ss;
    const std::string ind = pretty ? "  " : "";
    const std::string ind2 = pretty ? "    " : "";
    const std::string ind3 = pretty ? "      " : "";
    const std::string nl = pretty ? "\n" : "";

    ss << "{" << nl;
    ss << ind << "\"engine_status\": \"" << engine_status_to_string(status) << "\"," << nl;
    ss << ind << "\"timestamp_ns\": " << timestamp_ns << "," << nl;
    ss << ind << "\"duration_sec\": " << std::fixed << std::setprecision(3) << duration_sec << "," << nl;

    // Traffic Summary
    ss << ind << "\"traffic\": {" << nl;
    ss << ind2 << "\"total_packets\": " << total_packets << "," << nl;
    ss << ind2 << "\"total_bytes\": " << total_bytes << "," << nl;
    ss << ind2 << "\"packets_per_sec\": " << std::fixed << std::setprecision(2) << packets_per_sec << "," << nl;
    ss << ind2 << "\"bytes_per_sec\": " << std::fixed << std::setprecision(2) << bytes_per_sec << "," << nl;
    ss << ind2 << "\"mb_per_sec\": " << std::fixed << std::setprecision(2) << (bytes_per_sec / (1024.0 * 1024.0)) << nl;
    ss << ind << "}," << nl;

    // Flows Summary
    ss << ind << "\"flows_summary\": {" << nl;
    ss << ind2 << "\"total_flows\": " << total_flows << "," << nl;
    ss << ind2 << "\"active_flows\": " << active_flows << "," << nl;
    ss << ind2 << "\"completed_flows\": " << completed_flows << nl;
    ss << ind << "}," << nl;

    // Protocol Breakdown
    ss << ind << "\"protocols\": {" << nl;
    ss << ind2 << "\"transport\": {" << nl;
    ss << ind3 << "\"tcp\": " << tcp_flows << "," << nl;
    ss << ind3 << "\"udp\": " << udp_flows << "," << nl;
    ss << ind3 << "\"other\": " << other_l4_flows << nl;
    ss << ind2 << "}," << nl;
    ss << ind2 << "\"application\": {" << nl;
    ss << ind3 << "\"tls\": " << tls_flows << "," << nl;
    ss << ind3 << "\"http\": " << http_flows << "," << nl;
    ss << ind3 << "\"dns\": " << dns_flows << "," << nl;
    ss << ind3 << "\"unknown\": " << unknown_l7_flows << nl;
    ss << ind2 << "}" << nl;
    ss << ind << "}," << nl;

    // Policy Verdicts
    ss << ind << "\"policy\": {" << nl;
    ss << ind2 << "\"blocked_packets\": " << blocked_packets << "," << nl;
    ss << ind2 << "\"alert_packets\": " << alert_packets << "," << nl;
    ss << ind2 << "\"blocked_flows\": " << blocked_flows << "," << nl;
    ss << ind2 << "\"allowed_flows\": " << allowed_flows << nl;
    ss << ind << "}," << nl;

    // Errors
    ss << ind << "\"errors\": {" << nl;
    ss << ind2 << "\"malformed_packets\": " << malformed_packets << "," << nl;
    ss << ind2 << "\"unroutable_packets\": " << unroutable_packets << nl;
    ss << ind << "}," << nl;

    // Stage 8 Threat & Anomaly Metrics
    ss << ind << "\"threat_metrics\": {" << nl;
    ss << ind2 << "\"total_alerts_generated\": " << threat_stats.total_alerts_generated << "," << nl;
    ss << ind2 << "\"total_alerts_dropped\": " << threat_stats.total_alerts_dropped << "," << nl;
    ss << ind2 << "\"port_scan_alerts\": " << threat_stats.port_scan_alerts << "," << nl;
    ss << ind2 << "\"syn_flood_alerts\": " << threat_stats.syn_flood_alerts << "," << nl;
    ss << ind2 << "\"dns_anomaly_alerts\": " << threat_stats.dns_anomaly_alerts << "," << nl;
    ss << ind2 << "\"signature_alerts\": " << threat_stats.signature_alerts << "," << nl;
    ss << ind2 << "\"severity_breakdown\": {" << nl;
    ss << ind3 << "\"critical\": " << threat_stats.critical_alerts << "," << nl;
    ss << ind3 << "\"high\": " << threat_stats.high_alerts << "," << nl;
    ss << ind3 << "\"medium\": " << threat_stats.medium_alerts << "," << nl;
    ss << ind3 << "\"low\": " << threat_stats.low_alerts << "," << nl;
    ss << ind3 << "\"info\": " << threat_stats.info_alerts << nl;
    ss << ind2 << "}" << nl;
    ss << ind << "}," << nl;

    // Workers
    ss << ind << "\"workers\": [" << nl;
    for (size_t i = 0; i < worker_stats.size(); ++i) {
        const auto& ws = worker_stats[i];
        size_t q_size = (i < worker_queue_sizes.size()) ? worker_queue_sizes[i] : 0;
        ss << ind2 << "{" << nl;
        ss << ind3 << "\"worker_id\": " << i << "," << nl;
        ss << ind3 << "\"packets_processed\": " << ws.packets_processed << "," << nl;
        ss << ind3 << "\"bytes_processed\": " << ws.bytes_processed << "," << nl;
        ss << ind3 << "\"flows_created\": " << ws.flows_created << "," << nl;
        ss << ind3 << "\"blocked_packets\": " << ws.blocked_packets << "," << nl;
        ss << ind3 << "\"alert_packets\": " << ws.alert_packets << "," << nl;
        ss << ind3 << "\"dpi_classified_flows\": " << ws.dpi_classified_flows << "," << nl;
        ss << ind3 << "\"malformed_packets\": " << ws.malformed_packets << "," << nl;
        ss << ind3 << "\"threat_alerts_generated\": " << ws.threat_alerts_generated << "," << nl;
        ss << ind3 << "\"threat_alerts_dropped\": " << ws.threat_alerts_dropped << "," << nl;
        ss << ind3 << "\"queue_size\": " << q_size << nl;
        ss << ind2 << "}" << (i + 1 < worker_stats.size() ? "," : "") << nl;
    }
    ss << ind << "]," << nl;

    // Security Alerts Sample
    ss << ind << "\"alerts\": [" << nl;
    for (size_t i = 0; i < alerts.size(); ++i) {
        const auto& a = alerts[i];
        ss << ind2 << "{" << nl;
        ss << ind3 << "\"alert_id\": " << a.alert_id << "," << nl;
        ss << ind3 << "\"timestamp_us\": " << a.timestamp_us << "," << nl;
        ss << ind3 << "\"severity\": \"" << severity_to_string(a.severity) << "\"," << nl;
        ss << ind3 << "\"category\": \"" << category_to_string(a.category) << "\"," << nl;
        ss << ind3 << "\"signature\": \"" << escape_json(a.signature_name) << "\"," << nl;
        ss << ind3 << "\"description\": \"" << escape_json(a.description) << "\"," << nl;
        ss << ind3 << "\"src_ip\": \"" << escape_json(a.src_ip.to_string()) << "\"," << nl;
        ss << ind3 << "\"dst_ip\": \"" << escape_json(a.dst_ip.to_string()) << "\"," << nl;
        ss << ind3 << "\"src_port\": " << a.src_port << "," << nl;
        ss << ind3 << "\"dst_port\": " << a.dst_port << "," << nl;
        ss << ind3 << "\"transport\": \"" << (a.transport == L4Type::TCP ? "TCP" : (a.transport == L4Type::UDP ? "UDP" : "Other")) << "\"," << nl;
        ss << ind3 << "\"trigger_reason\": \"" << escape_json(a.trigger_reason) << "\"," << nl;
        ss << ind3 << "\"matched_snippet\": \"" << escape_json(a.matched_snippet) << "\"" << nl;
        ss << ind2 << "}" << (i + 1 < alerts.size() ? "," : "") << nl;
    }
    ss << ind << "]," << nl;

    // Flow Records Sample
    ss << ind << "\"flows\": [" << nl;
    for (size_t i = 0; i < flows.size(); ++i) {
        const auto& f = flows[i];
        ss << ind2 << "{" << nl;
        ss << ind3 << "\"id\": \"" << escape_json(f.flow_id) << "\"," << nl;
        ss << ind3 << "\"src_ip\": \"" << escape_json(f.src_ip) << "\"," << nl;
        ss << ind3 << "\"dst_ip\": \"" << escape_json(f.dst_ip) << "\"," << nl;
        ss << ind3 << "\"src_port\": " << f.src_port << "," << nl;
        ss << ind3 << "\"dst_port\": " << f.dst_port << "," << nl;
        ss << ind3 << "\"protocol\": \"" << escape_json(f.transport_protocol) << "\"," << nl;
        ss << ind3 << "\"app_protocol\": \"" << escape_json(f.app_protocol) << "\"," << nl;
        ss << ind3 << "\"host\": \"" << escape_json(f.host_or_sni) << "\"," << nl;
        ss << ind3 << "\"tcp_state\": \"" << escape_json(f.tcp_state) << "\"," << nl;
        ss << ind3 << "\"verdict\": \"" << escape_json(f.policy_verdict) << "\"," << nl;
        ss << ind3 << "\"matched_rule\": \"" << escape_json(f.matched_rule_name) << "\"," << nl;
        ss << ind3 << "\"packets_fwd\": " << f.packets_forward << "," << nl;
        ss << ind3 << "\"packets_rev\": " << f.packets_reverse << "," << nl;
        ss << ind3 << "\"bytes_fwd\": " << f.bytes_forward << "," << nl;
        ss << ind3 << "\"bytes_rev\": " << f.bytes_reverse << "," << nl;
        ss << ind3 << "\"duration_ms\": " << f.duration_ms << "," << nl;
        ss << ind3 << "\"is_blocked\": " << (f.is_blocked ? "true" : "false") << nl;
        ss << ind2 << "}" << (i + 1 < flows.size() ? "," : "") << nl;
    }
    ss << ind << "]" << nl;

    ss << "}";
    return ss.str();
}

} // namespace dpi
