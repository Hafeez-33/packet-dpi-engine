#ifndef DPI_THREAT_SYN_FLOOD_DETECTOR_H
#define DPI_THREAT_SYN_FLOOD_DETECTOR_H

#include "dpi/flow/ip_address.h"
#include "dpi/protocols/protocol_types.h"
#include "dpi/threat/threat_config.h"
#include "dpi/threat/threat_types.h"
#include <unordered_map>
#include <vector>

namespace dpi {

/**
 * @brief State-aware TCP SYN flood and connection DoS anomaly detector.
 * 
 * Tracks 3-way handshake completion (SYN -> SYN-ACK -> ACK/RST) and flags
 * abnormal half-open connection accumulation and uncompleted SYN burst rates.
 */
class SynFloodDetector {
public:
    explicit SynFloodDetector(const SynFloodConfig& config = {}) noexcept;

    /**
     * @brief Inspects TCP packet state for SYN flood signatures.
     * @return true if a SYN flood alert was triggered.
     */
    bool check_packet(const ParsedPacket& packet, uint64_t timestamp_us, SecurityAlert& out_alert);

    /**
     * @brief Cleans up expired half-open connections and stale source trackers.
     */
    void cleanup_expired(uint64_t current_time_us);

    /**
     * @brief Resets detector state.
     */
    void reset();

    size_t tracked_sources_count() const noexcept { return sources_.size(); }

private:
    struct HalfOpenKey {
        IPAddress dst_ip{};
        uint16_t src_port{0};
        uint16_t dst_port{0};

        bool operator==(const HalfOpenKey& o) const noexcept {
            return src_port == o.src_port && dst_port == o.dst_port && dst_ip == o.dst_ip;
        }
    };

    struct HalfOpenKeyHasher {
        size_t operator()(const HalfOpenKey& k) const noexcept {
            size_t h = IPAddressHasher{}(k.dst_ip);
            h ^= (static_cast<size_t>(k.src_port) << 16) | k.dst_port;
            return h;
        }
    };

    struct SourceTracker {
        uint64_t window_start_us{0};
        uint64_t last_seen_us{0};
        uint64_t syn_attempts{0};
        uint64_t completed_handshakes{0};
        std::unordered_map<HalfOpenKey, uint64_t, HalfOpenKeyHasher> half_open_conns{};
        bool alert_emitted{false};
    };

    void enforce_capacity_limits();

    SynFloodConfig config_;
    std::unordered_map<IPAddress, SourceTracker, IPAddressHasher> sources_{};
};

} // namespace dpi

#endif // DPI_THREAT_SYN_FLOOD_DETECTOR_H
