#ifndef DPI_THREAT_PORT_SCAN_DETECTOR_H
#define DPI_THREAT_PORT_SCAN_DETECTOR_H

#include "dpi/flow/ip_address.h"
#include "dpi/protocols/protocol_types.h"
#include "dpi/threat/threat_config.h"
#include "dpi/threat/threat_types.h"
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace dpi {

/**
 * @brief State tracker for vertical and horizontal port scan detection with bounded memory.
 */
class PortScanDetector {
public:
    explicit PortScanDetector(const PortScanConfig& config = {}) noexcept;

    /**
     * @brief Evaluates an outgoing packet for port scan signatures.
     * @return true if a new scan alert was triggered.
     */
    bool check_packet(const ParsedPacket& packet, uint64_t timestamp_us, SecurityAlert& out_alert);

    /**
     * @brief Cleans up expired scan state trackers beyond the observation window.
     */
    void cleanup_expired(uint64_t current_time_us);

    /**
     * @brief Resets all internal tracking state.
     */
    void reset();

    size_t tracked_sources_count() const noexcept { return vertical_trackers_.size(); }

private:
    struct VerticalTracker {
        uint64_t window_start_us{0};
        uint64_t last_seen_us{0};
        std::unordered_map<IPAddress, std::unordered_set<uint16_t>, IPAddressHasher> host_to_ports{};
        bool alert_emitted{false};
    };

    struct HorizontalTracker {
        uint64_t window_start_us{0};
        uint64_t last_seen_us{0};
        std::unordered_map<uint16_t, std::unordered_set<IPAddress, IPAddressHasher>> port_to_hosts{};
        bool alert_emitted{false};
    };

    void enforce_capacity_limits();

    PortScanConfig config_;
    std::unordered_map<IPAddress, VerticalTracker, IPAddressHasher> vertical_trackers_{};
    std::unordered_map<IPAddress, HorizontalTracker, IPAddressHasher> horizontal_trackers_{};
};

} // namespace dpi

#endif // DPI_THREAT_PORT_SCAN_DETECTOR_H
