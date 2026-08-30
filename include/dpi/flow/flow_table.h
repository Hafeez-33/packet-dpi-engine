#ifndef DPI_FLOW_FLOW_TABLE_H
#define DPI_FLOW_FLOW_TABLE_H

#include "dpi/flow/flow_entry.h"
#include "dpi/flow/flow_key.h"
#include "dpi/flow/flow_types.h"
#include "dpi/packet/pcap_types.h"
#include "dpi/protocols/parsed_packet.h"
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <unordered_map>

namespace dpi {

/**
 * @brief Configurable timeout durations for various protocol states.
 */
struct FlowTimeoutConfig {
    uint64_t tcp_syn_timeout_us{10 * 1000000ULL};          // 10 seconds for incomplete handshakes
    uint64_t tcp_established_timeout_us{300 * 1000000ULL}; // 300 seconds for active TCP flows
    uint64_t tcp_closed_timeout_us{10 * 1000000ULL};        // 10 seconds post FIN/RST teardown
    uint64_t udp_idle_timeout_us{30 * 1000000ULL};          // 30 seconds for UDP sessions
    uint64_t generic_timeout_us{60 * 1000000ULL};           // 60 seconds for other traffic
};

/**
 * @brief High-performance single-threaded hash-based flow table.
 * 
 * Manages flow lifecycles, normalizes bidirectional packets to canonical FlowEntries,
 * tracks per-flow statistics and observational TCP states, and handles explicit on-demand eviction.
 */
class FlowTable {
public:
    FlowTable() = default;

    /**
     * @brief Ingest a ParsedPacket, creating or updating the matching FlowEntry.
     * @param packet The decoded packet from Stage 2
     * @param timestamp_us Packet timestamp normalized to microseconds
     * @param wire_bytes Original wire length of the packet in bytes
     * @return Shared pointer to the updated FlowEntry, or nullptr if packet is invalid / unsupported
     */
    std::shared_ptr<FlowEntry> process_packet(const ParsedPacket& packet,
                                              uint64_t timestamp_us,
                                              size_t wire_bytes);

    /**
     * @brief Convenience overload integrating Stage 1 PacketRecord with Stage 2 ParsedPacket.
     * @param record The raw PCAP packet record containing wire header metadata
     * @param packet The parsed protocol representation
     * @param is_nanoseconds Whether the PCAP file has nanosecond resolution timestamps
     * @return Shared pointer to the updated FlowEntry, or nullptr if packet is invalid / unsupported
     */
    std::shared_ptr<FlowEntry> process_packet(const PacketRecord& record,
                                              const ParsedPacket& packet,
                                              bool is_nanoseconds = false);

    /**
     * @brief Find an existing flow by its canonical FlowKey.
     * @param key The canonical 5-tuple key
     * @return Shared pointer to FlowEntry if found, nullptr otherwise
     */
    std::shared_ptr<FlowEntry> find_flow(const FlowKey& key) const;

    /**
     * @brief Number of active flows in the table.
     */
    size_t size() const noexcept { return table_.size(); }

    /**
     * @brief True if the table contains no flows.
     */
    bool empty() const noexcept { return table_.empty(); }

    /**
     * @brief Clears all flows from the table.
     */
    void clear() noexcept { table_.clear(); }

    /**
     * @brief Scans the flow table and evicts all flows that have exceeded their idle timeout.
     * @param current_time_us Current microsecond timestamp against which idle times are evaluated
     * @return Number of expired flows evicted from the table
     */
    size_t cleanup_expired(uint64_t current_time_us);

    /**
     * @brief Iterate through all active flows.
     * @param visitor Callback function invoked for each flow entry
     */
    void for_each_flow(const std::function<void(const std::shared_ptr<FlowEntry>&)>& visitor) const;

    const FlowTimeoutConfig& timeout_config() const noexcept { return timeout_config_; }
    void set_timeout_config(const FlowTimeoutConfig& config) noexcept { timeout_config_ = config; }

    // Rule & Policy Engine Integration
    void set_rule_engine(std::shared_ptr<class RuleEngine> engine) noexcept { rule_engine_ = engine; }
    std::shared_ptr<class RuleEngine> rule_engine() const noexcept { return rule_engine_; }

private:
    uint64_t get_timeout_for_flow(const FlowEntry& entry) const noexcept;

    std::unordered_map<FlowKey, std::shared_ptr<FlowEntry>, FlowKeyHasher> table_{};
    FlowTimeoutConfig timeout_config_{};
    std::shared_ptr<class RuleEngine> rule_engine_{nullptr};
};

} // namespace dpi

#endif // DPI_FLOW_FLOW_TABLE_H
