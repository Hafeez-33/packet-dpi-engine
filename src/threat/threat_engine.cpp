#include "dpi/threat/threat_engine.h"
#include "dpi/flow/flow_types.h"

namespace dpi {

ThreatEngine::ThreatEngine(const ThreatConfig& config)
    : config_(config),
      port_scan_detector_(config.port_scan),
      syn_flood_detector_(config.syn_flood),
      dns_anomaly_detector_(config.dns_anomaly),
      signature_matcher_(config.signature) {
    signature_matcher_.load_default_signatures();
}

void ThreatEngine::load_default_signatures() {
    signature_matcher_.load_default_signatures();
}

void ThreatEngine::inspect_packet(const PacketRecord& record,
                                  const ParsedPacket& parsed,
                                  const FlowEntry* flow,
                                  bool is_nanoseconds,
                                  std::vector<SecurityAlert>& alerts_out) {
    if (!config_.enabled || !parsed.is_valid()) {
        return;
    }

    uint64_t ts_us = normalize_timestamp_us(record.header.ts_sec, record.header.ts_usec, is_nanoseconds);

    // Periodic state cleanup every 1024 packets
    if (++packets_since_cleanup_ >= 1024) {
        cleanup(ts_us);
        packets_since_cleanup_ = 0;
    }

    // 1. Port Scan Anomaly Detection
    SecurityAlert port_scan_alert;
    if (port_scan_detector_.check_packet(parsed, ts_us, port_scan_alert)) {
        port_scan_alert.alert_id = next_alert_id_++;
        alerts_out.push_back(std::move(port_scan_alert));
    }

    // 2. TCP SYN Flood / DoS Anomaly Detection
    if (parsed.is_tcp()) {
        SecurityAlert syn_alert;
        if (syn_flood_detector_.check_packet(parsed, ts_us, syn_alert)) {
            syn_alert.alert_id = next_alert_id_++;
            alerts_out.push_back(std::move(syn_alert));
        }
    }

    // 3. DNS Tunneling & DGA Anomaly Detection
    if (flow != nullptr && flow->is_classified()) {
        const auto& l7 = flow->l7_metadata();
        if (l7.protocol == AppProtocol::DNS && !l7.dns.qname.empty()) {
            SecurityAlert dns_alert;
            if (dns_anomaly_detector_.check_dns_query(l7.dns.qname, parsed, ts_us, dns_alert)) {
                dns_alert.alert_id = next_alert_id_++;
                alerts_out.push_back(std::move(dns_alert));
            }
        }
    }

    // 4. L7 Payload Signature Matching
    L7Metadata fallback_l7{};
    const L7Metadata& l7_ref = (flow != nullptr) ? flow->l7_metadata() : fallback_l7;

    const uint8_t* payload_ptr = reinterpret_cast<const uint8_t*>(parsed.l7_payload.data());
    size_t payload_len = parsed.l7_payload.size();

    SecurityAlert sig_alert;
    if (signature_matcher_.match(parsed, l7_ref, payload_ptr, payload_len, ts_us, sig_alert)) {
        sig_alert.alert_id = next_alert_id_++;
        alerts_out.push_back(std::move(sig_alert));
    }
}

void ThreatEngine::cleanup(uint64_t current_time_us) {
    port_scan_detector_.cleanup_expired(current_time_us);
    syn_flood_detector_.cleanup_expired(current_time_us);
}

} // namespace dpi
