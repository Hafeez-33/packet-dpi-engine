#ifndef DPI_THREAT_DNS_ANOMALY_DETECTOR_H
#define DPI_THREAT_DNS_ANOMALY_DETECTOR_H

#include "dpi/flow/ip_address.h"
#include "dpi/protocols/protocol_types.h"
#include "dpi/threat/threat_config.h"
#include "dpi/threat/threat_types.h"
#include <string_view>

namespace dpi {

/**
 * @brief Heuristic detector for DNS tunneling, data exfiltration, and DGA domain anomalies.
 */
class DnsAnomalyDetector {
public:
    explicit DnsAnomalyDetector(const DnsAnomalyConfig& config = {}) noexcept;

    /**
     * @brief Evaluates a DNS domain name query for statistical and structural anomalies.
     * @return true if an anomaly alert was triggered.
     */
    bool check_dns_query(std::string_view qname,
                         const ParsedPacket& packet,
                         uint64_t timestamp_us,
                         SecurityAlert& out_alert) const;

private:
    DnsAnomalyConfig config_;
};

} // namespace dpi

#endif // DPI_THREAT_DNS_ANOMALY_DETECTOR_H
