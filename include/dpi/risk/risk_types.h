#ifndef DPI_RISK_TYPES_H
#define DPI_RISK_TYPES_H

#include "dpi/flow/ip_address.h"
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace dpi {

/**
 * @brief Categorical risk severity tiers normalized to 0-100 score ranges.
 */
enum class RiskLevel : uint8_t {
    None = 0,    // 0 - 19: Clean / Normal traffic
    Low,         // 20 - 39: Minor anomalous behavior
    Medium,      // 40 - 59: Notable risk / multiple heuristic flags
    High,        // 60 - 79: Confirmed policy breach / severe anomaly
    Critical     // 80 - 100: Active exploit / C2 / Exfiltration / Malicious attack
};

/**
 * @brief Converts RiskLevel enum to human-readable string.
 */
std::string_view risk_level_to_string(RiskLevel level) noexcept;

/**
 * @brief Parses RiskLevel from string view.
 */
RiskLevel string_to_risk_level(std::string_view str) noexcept;

/**
 * @brief Stream-calculated behavioral statistics maintained per flow.
 */
struct BehavioralMetrics {
    uint32_t fwd_packets{0};
    uint32_t rev_packets{0};
    uint64_t fwd_bytes{0};
    uint64_t rev_bytes{0};

    // Rolling inter-arrival time (IAT) statistics (milliseconds)
    uint64_t last_packet_ts_us{0};
    uint32_t iat_count{0};
    double mean_iat_ms{0.0};
    double m2_iat_ms2{0.0};      // Welford's algorithm sum of squared differences
    double iat_variance_ms2{0.0};
    double iat_stddev_ms{0.0};
    double iat_jitter_ratio{0.0}; // Coefficient of Variation: stddev / mean

    // Directional byte asymmetry ratio: fwd_bytes / max(1, rev_bytes)
    double byte_ratio{1.0};

    // Packet size distribution histogram
    uint32_t small_packets{0};   // < 128 bytes
    uint32_t medium_packets{0};  // 128 - 1024 bytes
    uint32_t large_packets{0};   // > 1024 bytes

    // Behavioral anomaly flags
    bool is_beaconing{false};
    double beacon_interval_ms{0.0};
    double beacon_jitter{0.0};

    bool is_exfiltration{false};
    double exfiltration_ratio{0.0};
};

/**
 * @brief Normalized composite flow risk evaluation.
 */
struct FlowRiskScore {
    uint8_t score{0}; // 0 - 100
    RiskLevel level{RiskLevel::None};
    std::vector<std::string> contributing_factors{}; // Max 5 factors
};

/**
 * @brief Aggregated risk profile for an endpoint IP address.
 */
struct HostRiskProfile {
    IPAddress ip{};
    uint32_t total_flows{0};
    uint32_t high_risk_flows{0};
    uint8_t max_flow_risk{0};
    double average_flow_risk{0.0};
    uint64_t last_seen_us{0};
    bool has_beaconing_flow{false};
    bool has_exfiltration_flow{false};
};

/**
 * @brief Summary statistics of risk scoring across the entire engine.
 */
struct RiskStatsSnapshot {
    uint64_t total_flows_evaluated{0};
    uint64_t risk_none_count{0};
    uint64_t risk_low_count{0};
    uint64_t risk_medium_count{0};
    uint64_t risk_high_count{0};
    uint64_t risk_critical_count{0};
    uint64_t beaconing_flows_detected{0};
    uint64_t exfiltration_flows_detected{0};
    std::vector<HostRiskProfile> top_risky_hosts{};
};

} // namespace dpi

#endif // DPI_RISK_TYPES_H
