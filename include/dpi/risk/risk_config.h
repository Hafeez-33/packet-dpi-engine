#ifndef DPI_RISK_CONFIG_H
#define DPI_RISK_CONFIG_H

#include <cstdint>

namespace dpi {

struct BeaconingConfig {
    bool enabled{true};
    uint32_t min_intervals{8};           // Minimum consecutive intervals to evaluate periodicity
    double max_jitter_ratio{0.15};       // Max coefficient of variation (stddev / mean) for beaconing
    double min_interval_ms{50.0};        // 50 ms minimum interval
    double max_interval_ms{3600000.0};   // 1 hour maximum interval
};

struct ExfiltrationConfig {
    bool enabled{true};
    uint64_t min_fwd_bytes{1048576};     // 1 MB minimum outbound data
    double min_byte_ratio{20.0};         // Outbound / Inbound ratio threshold
};

struct RiskScoringWeights {
    uint8_t threat_alert_critical{50};
    uint8_t threat_alert_high{35};
    uint8_t threat_alert_medium{20};
    uint8_t threat_alert_low{10};

    uint8_t policy_blocked{40};
    uint8_t policy_alert{25};

    uint8_t beaconing_detected{35};
    uint8_t exfiltration_detected{30};

    uint8_t unclassified_high_port{15};  // High destination port with Unknown L7 protocol
    uint8_t large_packet_burst{10};      // > 90% large packets with zero response
};

struct RiskConfig {
    bool enabled{true};
    BeaconingConfig beaconing{};
    ExfiltrationConfig exfiltration{};
    RiskScoringWeights weights{};
    size_t max_host_profiles{4096};
};

} // namespace dpi

#endif // DPI_RISK_CONFIG_H
