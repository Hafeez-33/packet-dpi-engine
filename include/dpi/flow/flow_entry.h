#ifndef DPI_FLOW_FLOW_ENTRY_H
#define DPI_FLOW_FLOW_ENTRY_H

#include "dpi/dpi/l7_types.h"
#include "dpi/flow/flow_key.h"
#include "dpi/flow/flow_stats.h"
#include "dpi/flow/flow_types.h"
#include "dpi/flow/tcp_state_machine.h"
#include "dpi/protocols/parsed_packet.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace dpi {

/**
 * @brief Represents an active or completed network flow record in the flow table.
 * 
 * Stores canonical 5-tuple metadata, directional packet/byte statistics, timestamps,
 * TCP state, and classified Layer-7 metadata. Utilizes a temporary, bounded reassembly
 * buffer that is immediately released upon classification or timeout to ensure zero memory bloat.
 */
class FlowEntry {
public:
    static constexpr size_t DEFAULT_MAX_DPI_BUFFER_SIZE = 8192; // 8 KB upper bound

    FlowEntry(const FlowKey& key, FlowDirection init_dir, uint64_t timestamp_us) noexcept;

    const FlowKey& key() const noexcept { return key_; }
    FlowDirection initial_direction() const noexcept { return initial_direction_; }
    FlowState state() const noexcept { return state_; }
    const FlowStats& stats() const noexcept { return stats_; }
    const TcpStateMachine& tcp_state_machine() const noexcept { return tcp_sm_; }

    // Layer-7 Inspection & Classification
    const L7Metadata& l7_metadata() const noexcept { return l7_meta_; }
    bool is_classified() const noexcept { return l7_meta_.is_classified; }
    bool is_dpi_complete() const noexcept { return dpi_complete_; }
    std::string_view dpi_buffer() const noexcept { return dpi_buffer_; }
    size_t dpi_buffer_size() const noexcept { return dpi_buffer_.size(); }

    /**
     * @brief Appends incoming payload to the temporary reassembly buffer up to max_buffer_size.
     */
    void append_dpi_payload(std::string_view payload,
                            size_t max_buffer_size = DEFAULT_MAX_DPI_BUFFER_SIZE) noexcept;

    /**
     * @brief Finalizes flow classification and immediately releases the temporary reassembly buffer.
     */
    void finalize_classification(const L7Metadata& meta) noexcept;

    /**
     * @brief Abandons DPI inspection (e.g. when limit is reached without match) and releases buffer.
     */
    void abandon_dpi() noexcept;

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

    // Layer-7 Classification & Reassembly
    L7Metadata l7_meta_{};
    std::string dpi_buffer_{}; // Temporary bounded buffer
    bool dpi_complete_{false}; // True once classified or abandoned
};

} // namespace dpi

#endif // DPI_FLOW_FLOW_ENTRY_H
