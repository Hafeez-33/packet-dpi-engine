#ifndef DPI_FLOW_FLOW_TYPES_H
#define DPI_FLOW_FLOW_TYPES_H

#include <cstdint>
#include <string_view>

namespace dpi {

/**
 * @brief Direction of a packet relative to the flow's canonical orientation.
 */
enum class FlowDirection : uint8_t {
    Forward = 0, // In direction of canonical initiator (low -> high or first packet)
    Reverse = 1  // In opposite direction (high -> low or return traffic)
};

/**
 * @brief Transport protocol indicator for flow classification.
 */
enum class FlowProtocol : uint8_t {
    Other = 0,
    TCP   = 6,
    UDP   = 17
};

/**
 * @brief High-level lifecycle state of a network flow.
 */
enum class FlowState : uint8_t {
    New = 0,
    Active,
    Established,
    Closing,
    Closed,
    Expired
};

/**
 * @brief Observational TCP state tracking for network flows.
 */
enum class TcpState : uint8_t {
    New = 0,
    SynSent,
    SynReceived,
    Established,
    FinWait,
    CloseWait,
    Closing,
    LastAck,
    Closed,
    Reset
};

/**
 * @brief Convert FlowDirection to human-readable string.
 */
constexpr std::string_view flow_direction_to_string(FlowDirection dir) noexcept {
    switch (dir) {
        case FlowDirection::Forward: return "Forward";
        case FlowDirection::Reverse: return "Reverse";
        default: return "Unknown";
    }
}

/**
 * @brief Convert FlowState to human-readable string.
 */
constexpr std::string_view flow_state_to_string(FlowState state) noexcept {
    switch (state) {
        case FlowState::New: return "New";
        case FlowState::Active: return "Active";
        case FlowState::Established: return "Established";
        case FlowState::Closing: return "Closing";
        case FlowState::Closed: return "Closed";
        case FlowState::Expired: return "Expired";
        default: return "Unknown";
    }
}

/**
 * @brief Convert TcpState to human-readable string.
 */
constexpr std::string_view tcp_state_to_string(TcpState state) noexcept {
    switch (state) {
        case TcpState::New: return "NEW";
        case TcpState::SynSent: return "SYN_SENT";
        case TcpState::SynReceived: return "SYN_RECEIVED";
        case TcpState::Established: return "ESTABLISHED";
        case TcpState::FinWait: return "FIN_WAIT";
        case TcpState::CloseWait: return "CLOSE_WAIT";
        case TcpState::Closing: return "CLOSING";
        case TcpState::LastAck: return "LAST_ACK";
        case TcpState::Closed: return "CLOSED";
        case TcpState::Reset: return "RESET";
        default: return "UNKNOWN";
    }
}

/**
 * @brief Normalizes PCAP PacketHeader timestamps to uniform microsecond integers (uint64_t).
 * 
 * Classic PCAP files can store fractional timestamps in either microseconds (magic 0xa1b2c3d4)
 * or nanoseconds (magic 0xa1b23c4d). This utility ensures all flow timestamps are consistently
 * represented in microseconds.
 * 
 * @param ts_sec Seconds component
 * @param ts_frac Fractional component (microseconds or nanoseconds)
 * @param is_nanoseconds True if PCAP header specifies nanosecond resolution
 * @return Timestamp in integer microseconds since epoch
 */
inline uint64_t normalize_timestamp_us(uint32_t ts_sec, uint32_t ts_frac, bool is_nanoseconds = false) noexcept {
    uint64_t sec_us = static_cast<uint64_t>(ts_sec) * 1000000ULL;
    uint64_t frac_us = is_nanoseconds ? (static_cast<uint64_t>(ts_frac) / 1000ULL) : static_cast<uint64_t>(ts_frac);
    return sec_us + frac_us;
}

} // namespace dpi

#endif // DPI_FLOW_FLOW_TYPES_H
