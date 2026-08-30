#include "dpi/flow/flow_entry.h"

namespace dpi {

FlowEntry::FlowEntry(const FlowKey& key, FlowDirection init_dir, uint64_t timestamp_us) noexcept
    : key_(key), initial_direction_(init_dir), state_(FlowState::New) {
    stats_.first_seen_us = timestamp_us;
    stats_.last_seen_us = timestamp_us;
}

void FlowEntry::update(const ParsedPacket& packet, FlowDirection dir,
                       uint64_t timestamp_us, size_t wire_bytes) noexcept {
    size_t payload_len = packet.l7_payload.size();
    stats_.record_packet(dir, timestamp_us, wire_bytes, payload_len);

    if (packet.is_tcp()) {
        tcp_sm_.process_packet(packet.tcp, dir, payload_len);

        switch (tcp_sm_.state()) {
            case TcpState::Established:
                state_ = FlowState::Established;
                break;
            case TcpState::FinWait:
            case TcpState::CloseWait:
            case TcpState::Closing:
            case TcpState::LastAck:
                state_ = FlowState::Closing;
                break;
            case TcpState::Closed:
            case TcpState::Reset:
                state_ = FlowState::Closed;
                break;
            case TcpState::SynSent:
            case TcpState::SynReceived:
            case TcpState::New:
            default:
                state_ = FlowState::Active;
                break;
        }
    } else if (packet.is_udp()) {
        if (stats_.forward.packets > 0 && stats_.reverse.packets > 0) {
            state_ = FlowState::Established;
        } else {
            state_ = FlowState::Active;
        }
    } else {
        state_ = FlowState::Active;
    }
}

bool FlowEntry::is_expired(uint64_t current_time_us, uint64_t idle_timeout_us) const noexcept {
    if (current_time_us <= stats_.last_seen_us) {
        return false;
    }
    return (current_time_us - stats_.last_seen_us) > idle_timeout_us;
}

} // namespace dpi
