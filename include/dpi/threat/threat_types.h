#ifndef DPI_THREAT_THREAT_TYPES_H
#define DPI_THREAT_THREAT_TYPES_H

#include "dpi/flow/flow_key.h"
#include "dpi/flow/ip_address.h"
#include "dpi/dpi/l7_types.h"
#include "dpi/protocols/protocol_types.h"
#include <cstdint>
#include <string>
#include <string_view>

namespace dpi {

/**
 * @brief Security alert severity levels.
 */
enum class AlertSeverity : uint8_t {
    Info,
    Low,
    Medium,
    High,
    Critical
};

/**
 * @brief Threat classification categories.
 */
enum class ThreatCategory : uint8_t {
    PortScan,
    SynFlood,
    DnsTunneling,
    DnsDgaAnomaly,
    SqlInjection,
    DirectoryTraversal,
    SuspiciousUserAgent,
    MalformedTraffic,
    CustomSignature
};

/**
 * @brief Structured threat detection alert event.
 */
struct SecurityAlert {
    uint64_t alert_id{0};
    uint64_t timestamp_us{0};
    AlertSeverity severity{AlertSeverity::Medium};
    ThreatCategory category{ThreatCategory::PortScan};
    std::string signature_name{};
    std::string description{};
    IPAddress src_ip{};
    IPAddress dst_ip{};
    uint16_t src_port{0};
    uint16_t dst_port{0};
    L4Type transport{L4Type::None};
    AppProtocol app_protocol{AppProtocol::Unknown};
    std::string trigger_reason{};
    std::string matched_snippet{};
};

/**
 * @brief Summary metrics of generated and dropped alerts.
 */
struct ThreatStatsSnapshot {
    uint64_t total_alerts_generated{0};
    uint64_t total_alerts_dropped{0};
    uint64_t port_scan_alerts{0};
    uint64_t syn_flood_alerts{0};
    uint64_t dns_anomaly_alerts{0};
    uint64_t signature_alerts{0};
    uint64_t critical_alerts{0};
    uint64_t high_alerts{0};
    uint64_t medium_alerts{0};
    uint64_t low_alerts{0};
    uint64_t info_alerts{0};
};

std::string severity_to_string(AlertSeverity severity);
std::string category_to_string(ThreatCategory category);
AlertSeverity string_to_severity(std::string_view str) noexcept;
ThreatCategory string_to_category(std::string_view str) noexcept;

} // namespace dpi

#endif // DPI_THREAT_THREAT_TYPES_H
