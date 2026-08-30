#ifndef DPI_THREAT_THREAT_ENGINE_H
#define DPI_THREAT_THREAT_ENGINE_H

#include "dpi/flow/flow_entry.h"
#include "dpi/packet/pcap_types.h"
#include "dpi/protocols/protocol_types.h"
#include "dpi/threat/dns_anomaly_detector.h"
#include "dpi/threat/payload_signature_matcher.h"
#include "dpi/threat/port_scan_detector.h"
#include "dpi/threat/syn_flood_detector.h"
#include "dpi/threat/threat_config.h"
#include "dpi/threat/threat_types.h"
#include <memory>
#include <vector>

namespace dpi {

/**
 * @brief Central coordinator for worker-local threat detection, anomaly analysis,
 * and signature evaluation.
 */
class ThreatEngine {
public:
    explicit ThreatEngine(const ThreatConfig& config = {});

    /**
     * @brief Evaluates an incoming packet and associated flow context for security threats.
     * Appends any triggered alerts to alerts_out.
     */
    void inspect_packet(const PacketRecord& record,
                        const ParsedPacket& parsed,
                        const FlowEntry* flow,
                        bool is_nanoseconds,
                        std::vector<SecurityAlert>& alerts_out);

    /**
     * @brief Performs periodic expiration and memory reclamation across internal anomaly tables.
     */
    void cleanup(uint64_t current_time_us);

    /**
     * @brief Loads custom or built-in threat signatures.
     */
    void load_default_signatures();

    PayloadSignatureMatcher& signature_matcher() noexcept { return signature_matcher_; }
    const ThreatConfig& config() const noexcept { return config_; }

private:
    ThreatConfig config_;
    PortScanDetector port_scan_detector_;
    SynFloodDetector syn_flood_detector_;
    DnsAnomalyDetector dns_anomaly_detector_;
    PayloadSignatureMatcher signature_matcher_;

    uint64_t next_alert_id_{1};
    uint64_t packets_since_cleanup_{0};
};

} // namespace dpi

#endif // DPI_THREAT_THREAT_ENGINE_H
