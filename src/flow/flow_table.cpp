#include "dpi/flow/flow_table.h"

namespace dpi {

std::shared_ptr<FlowEntry> FlowTable::process_packet(const PacketRecord& record,
                                                     const ParsedPacket& packet,
                                                     bool is_nanoseconds) {
    uint64_t ts_us = normalize_timestamp_us(record.header.ts_sec, record.header.ts_usec, is_nanoseconds);
    size_t wire_bytes = (record.header.orig_len > 0) ? record.header.orig_len : record.payload.size();
    return process_packet(packet, ts_us, wire_bytes);
}

std::shared_ptr<FlowEntry> FlowTable::process_packet(const ParsedPacket& packet,
                                                     uint64_t timestamp_us,
                                                     size_t wire_bytes) {
    if (!packet.is_valid()) {
        return nullptr;
    }

    // Only TCP and UDP transport protocols are tracked in Stage 3
    if (!packet.is_tcp() && !packet.is_udp()) {
        return nullptr;
    }

    auto [key, dir] = FlowKey::from_packet(packet);
    if (!key.src.ip.is_valid() || !key.dst.ip.is_valid()) {
        return nullptr;
    }

    auto it = table_.find(key);
    if (it == table_.end()) {
        auto entry = std::make_shared<FlowEntry>(key, dir, timestamp_us);
        entry->update(packet, dir, timestamp_us, wire_bytes);
        table_.emplace(key, entry);
        return entry;
    }

    it->second->update(packet, dir, timestamp_us, wire_bytes);
    return it->second;
}

std::shared_ptr<FlowEntry> FlowTable::find_flow(const FlowKey& key) const {
    auto it = table_.find(key);
    if (it != table_.end()) {
        return it->second;
    }
    return nullptr;
}

uint64_t FlowTable::get_timeout_for_flow(const FlowEntry& entry) const noexcept {
    if (entry.key().protocol == static_cast<uint8_t>(FlowProtocol::TCP)) {
        TcpState state = entry.tcp_state_machine().state();
        if (state == TcpState::SynSent || state == TcpState::SynReceived) {
            return timeout_config_.tcp_syn_timeout_us;
        }
        if (entry.tcp_state_machine().is_closed()) {
            return timeout_config_.tcp_closed_timeout_us;
        }
        if (entry.tcp_state_machine().is_established()) {
            return timeout_config_.tcp_established_timeout_us;
        }
        return timeout_config_.generic_timeout_us;
    }

    if (entry.key().protocol == static_cast<uint8_t>(FlowProtocol::UDP)) {
        return timeout_config_.udp_idle_timeout_us;
    }

    return timeout_config_.generic_timeout_us;
}

size_t FlowTable::cleanup_expired(uint64_t current_time_us) {
    size_t evicted = 0;
    auto it = table_.begin();
    while (it != table_.end()) {
        uint64_t timeout = get_timeout_for_flow(*it->second);
        if (it->second->is_expired(current_time_us, timeout)) {
            it = table_.erase(it);
            ++evicted;
        } else {
            ++it;
        }
    }
    return evicted;
}

void FlowTable::for_each_flow(const std::function<void(const std::shared_ptr<FlowEntry>&)>& visitor) const {
    for (const auto& pair : table_) {
        visitor(pair.second);
    }
}

} // namespace dpi
