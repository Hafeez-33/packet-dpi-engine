#ifndef DPI_FLOW_FLOW_STATS_H
#define DPI_FLOW_FLOW_STATS_H

#include "dpi/flow/flow_types.h"
#include <cstddef>
#include <cstdint>

namespace dpi {

/**
 * @brief Direction-specific traffic statistics.
 */
struct DirectionStats {
    uint64_t packets{0};
    uint64_t bytes{0};         // Total wire bytes
    uint64_t payload_bytes{0}; // Application layer payload bytes
};

/**
 * @brief Complete bidirectional flow statistics and timestamp tracking.
 */
struct FlowStats {
    uint64_t first_seen_us{0}; // Microsecond timestamp of first packet in flow
    uint64_t last_seen_us{0};  // Microsecond timestamp of most recent packet
    DirectionStats forward{};  // Traffic in forward direction
    DirectionStats reverse{};  // Traffic in reverse direction

    uint64_t total_packets() const noexcept {
        return forward.packets + reverse.packets;
    }

    uint64_t total_bytes() const noexcept {
        return forward.bytes + reverse.bytes;
    }

    uint64_t total_payload_bytes() const noexcept {
        return forward.payload_bytes + reverse.payload_bytes;
    }

    uint64_t duration_us() const noexcept {
        return last_seen_us >= first_seen_us ? (last_seen_us - first_seen_us) : 0;
    }

    /**
     * @brief Record packet reception and update timestamps and counters.
     */
    void record_packet(FlowDirection dir, uint64_t timestamp_us,
                       size_t wire_bytes, size_t payload_len) noexcept {
        if (first_seen_us == 0 || timestamp_us < first_seen_us) {
            first_seen_us = timestamp_us;
        }
        if (timestamp_us > last_seen_us) {
            last_seen_us = timestamp_us;
        }

        DirectionStats& target = (dir == FlowDirection::Forward) ? forward : reverse;
        target.packets += 1;
        target.bytes += wire_bytes;
        target.payload_bytes += payload_len;
    }
};

} // namespace dpi

#endif // DPI_FLOW_FLOW_STATS_H
