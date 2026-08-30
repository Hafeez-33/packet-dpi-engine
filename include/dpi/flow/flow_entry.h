#ifndef DPI_FLOW_FLOW_ENTRY_H
#define DPI_FLOW_FLOW_ENTRY_H

#include "dpi/flow/flow_key.h"
#include "dpi/flow/flow_stats.h"
#include "dpi/flow/flow_types.h"
#include "dpi/flow/tcp_state_machine.h"
#include "dpi/protocols/parsed_packet.h"
#include <cstddef>
#include <cstdint>

namespace dpi {

/**
 * @brief Represents an active or completed network flow record in the flow table.
 * 
 * Stores canonical 5-tuple metadata, directional packet/byte statistics, timestamps,
 * and TCP state without buffering packet payloads to maintain a minimal memory footprint.
 */
class FlowEntry {
public:
    FlowEntry(const FlowKey& key, FlowDirection init_dir, uint64_t timestamp_us) noexcept;

    const FlowKey& key() const noexcept { return key_; }
    FlowDirection initial_direction() const noexcept { return initial_direction_; }
    FlowState state() const noexcept { return state_; }
    const FlowStats& stats() const noexcept { return stats_; }
    const TcpStateMachine& tcp_state_machine() const noexcept { return tcp_sm_; }

    /**
     * @brief Ingest a parsed packet matching this flow and update stats, timestamps, and TCP state.
     * @param packet The parsed packet
     * @param dir Direction relative to flow key
     * @param timestamp_us Normalized packet timestamp in microseconds
     * @param wire_bytes Original wire length of the packet
     */
    void update(const ParsedPacket& packet, FlowDirection dir,
                uint64_t timestamp_us, size_t wire_bytes) noexcept;

    /**
     * @brief Checks whether the flow has been idle longer than the specified timeout duration.
     * @param current_time_us Current microsecond timestamp
     * @param idle_timeout_us Configured idle timeout duration in microseconds
     */
    bool is_expired(uint64_t current_time_us, uint64_t idle_timeout_us) const noexcept;

private:
    FlowKey key_{};
    FlowDirection initial_direction_{FlowDirection::Forward};
    FlowState state_{FlowState::New};
    FlowStats stats_{};
    TcpStateMachine tcp_sm_{};
};

} // namespace dpi

#endif // DPI_FLOW_FLOW_ENTRY_H
