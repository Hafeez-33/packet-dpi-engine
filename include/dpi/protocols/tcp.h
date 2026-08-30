#ifndef DPI_PROTOCOLS_TCP_H
#define DPI_PROTOCOLS_TCP_H

#include "dpi/protocols/protocol_types.h"
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace dpi {

/**
 * @brief TCP Control Flags.
 */
struct TcpFlags {
    bool fin{false};
    bool syn{false};
    bool rst{false};
    bool psh{false};
    bool ack{false};
    bool urg{false};
    bool ece{false};
    bool cwr{false};
    uint8_t raw{0};
};

/**
 * @brief Parsed TCP Header (RFC 793 / RFC 3168).
 */
struct TcpHeader {
    static constexpr size_t MIN_HEADER_SIZE = 20;

    uint16_t src_port{0};
    uint16_t dst_port{0};
    uint32_t seq_num{0};
    uint32_t ack_num{0};
    uint8_t data_offset{5};           // Header length in 32-bit words (5..15)
    TcpFlags flags{};
    uint16_t window_size{0};
    uint16_t checksum{0};
    uint16_t urgent_pointer{0};

    std::string_view options{};       // Zero-copy view of TCP options if data_offset > 5
    size_t header_length{MIN_HEADER_SIZE}; // data_offset * 4 in bytes
};

} // namespace dpi

#endif // DPI_PROTOCOLS_TCP_H
