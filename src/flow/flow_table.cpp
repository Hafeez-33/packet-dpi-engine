#include "dpi/dpi/dpi_engine.h"
#include "dpi/flow/flow_table.h"
#include "dpi/rules/rule_engine.h"

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

    // Only TCP and UDP transport protocols are tracked in Stage 3/4/5
    if (!packet.is_tcp() && !packet.is_udp()) {
        return nullptr;
    }

    auto [key, dir] = FlowKey::from_packet(packet);
    if (!key.src.ip.is_valid() || !key.dst.ip.is_valid()) {
        return nullptr;
    }

    std::shared_ptr<FlowEntry> entry;
    auto it = table_.find(key);
    if (it == table_.end()) {
        entry = std::make_shared<FlowEntry>(key, dir, timestamp_us);
        entry->update(packet, dir, timestamp_us, wire_bytes);
        if (rule_engine_) {
            PolicyVerdict v = rule_engine_->evaluate_l3_l4(key);
            entry->set_policy_verdict(v);
        }
        table_.emplace(key, entry);
    } else {
        entry = it->second;
        entry->update(packet, dir, timestamp_us, wire_bytes);
    }

    // Layer-7 DPI Inspection for unclassified flows
    if (!entry->is_dpi_complete() && packet.has_payload()) {
        if (packet.is_tcp()) {
            entry->append_dpi_payload(packet.l7_payload, FlowEntry::DEFAULT_MAX_DPI_BUFFER_SIZE);
            DpiResult res = DpiEngine::inspect(entry->dpi_buffer(),
                                               static_cast<uint8_t>(FlowProtocol::TCP),
                                               packet.tcp.src_port,
                                               packet.tcp.dst_port);
            if (res.matched) {
                entry->finalize_classification(res.metadata);
                if (rule_engine_) {
                    PolicyVerdict v = rule_engine_->evaluate_l7(key, entry->l7_metadata());
                    entry->set_policy_verdict(v);
                }
            } else if (entry->dpi_buffer_size() >= FlowEntry::DEFAULT_MAX_DPI_BUFFER_SIZE) {
                entry->abandon_dpi();
                if (rule_engine_ && !entry->has_final_verdict()) {
                    PolicyVerdict v = rule_engine_->evaluate_l7(key, entry->l7_metadata());
                    entry->set_policy_verdict(v);
                }
            }
        } else if (packet.is_udp()) {
            DpiResult res = DpiEngine::inspect(packet.l7_payload,
                                               static_cast<uint8_t>(FlowProtocol::UDP),
                                               packet.udp.src_port,
                                               packet.udp.dst_port);
            if (res.matched) {
                entry->finalize_classification(res.metadata);
                if (rule_engine_) {
                    PolicyVerdict v = rule_engine_->evaluate_l7(key, entry->l7_metadata());
                    entry->set_policy_verdict(v);
                }
            } else {
                entry->abandon_dpi();
                if (rule_engine_ && !entry->has_final_verdict()) {
                    PolicyVerdict v = rule_engine_->evaluate_l7(key, entry->l7_metadata());
                    entry->set_policy_verdict(v);
                }
            }
        }
    }

    return entry;
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
