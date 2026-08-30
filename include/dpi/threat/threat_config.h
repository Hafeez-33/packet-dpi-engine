#ifndef DPI_THREAT_THREAT_CONFIG_H
#define DPI_THREAT_THREAT_CONFIG_H

#include <cstddef>
#include <cstdint>

namespace dpi {

/**
 * @brief Configuration parameters for port scan detection heuristics.
 */
struct PortScanConfig {
    size_t vertical_port_threshold{15};     // Distinct destination ports on a single host
    size_t horizontal_host_threshold{15};   // Distinct destination hosts on a single port
    uint64_t window_us{5000000};            // Sliding observation window (default: 5.0s)
    size_t max_tracked_sources{4096};       // Hard memory cap on active tracking table
};

/**
 * @brief Configuration parameters for TCP SYN flood rate and half-open tracking.
 */
struct SynFloodConfig {
    size_t half_open_threshold{25};         // Max active half-open connections before alert
    size_t syn_rate_threshold{40};          // Max SYNs within window before alert
    uint64_t window_us{2000000};            // Sliding observation window (default: 2.0s)
    uint64_t half_open_timeout_us{10000000};// Timeout to evict stale unacknowledged SYNs (10.0s)
    size_t max_tracked_sources{4096};       // Hard memory cap on active tracking table
};

/**
 * @brief Configuration parameters for DNS tunneling and DGA anomaly heuristics.
 */
struct DnsAnomalyConfig {
    double max_entropy_threshold{3.75};     // Max Shannon entropy (bits/char) for QNAME
    size_t max_label_length{45};            // Max characters for any single subdomain label
    size_t max_fqdn_length{100};            // Max total characters for entire QNAME
    size_t max_subdomain_depth{4};          // Max label dot-depth before triggering anomaly
};

/**
 * @brief Configuration parameters for L7 payload pattern matching.
 */
struct SignatureConfig {
    size_t max_inspect_payload_bytes{4096}; // Bounded inspection window per packet
    size_t max_signatures{1024};            // Bounded signature rule count
    size_t max_pattern_length{256};         // Max pattern length in bytes
};

/**
 * @brief Master Threat Engine configuration.
 */
struct ThreatConfig {
    bool enabled{true};
    size_t max_alert_buffer_capacity{1000}; // Ring buffer capacity per worker thread
    PortScanConfig port_scan{};
    SynFloodConfig syn_flood{};
    DnsAnomalyConfig dns_anomaly{};
    SignatureConfig signature{};
};

} // namespace dpi

#endif // DPI_THREAT_THREAT_CONFIG_H
