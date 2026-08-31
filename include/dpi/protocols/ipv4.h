#ifndef DPI_PROTOCOLS_IPV4_H
#define DPI_PROTOCOLS_IPV4_H

#include "dpi/protocols/protocol_types.h"
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace dpi {

/**
 * @brief IPv4 Header control flags.
 */
struct IPv4Flags {
    bool reserved{false};
    bool dont_fragment{false}; // DF flag
    bool more_fragments{false}; // MF flag
};

/**
 * @brief Parsed IPv4 header with fragmentation details and options.
 */
struct IPv4Header {
    static constexpr size_t MIN_HEADER_SIZE = 20;

    uint8_t version{4};
    uint8_t ihl{5};                  // Internet Header Length in 32-bit words (5..15)
    uint8_t dscp{0};                 // Differentiated Services Code Point (6 bits)
    uint8_t ecn{0};                  // Explicit Congestion Notification (2 bits)
    uint16_t total_length{0};        // Total wire length of IP packet (header + payload)
    uint16_t identification{0};
    IPv4Flags flags{};
    uint16_t fragment_offset{0};     // In 8-byte units (0..8191)
    uint16_t fragment_offset_bytes{0}; // fragment_offset * 8
    uint8_t ttl{0};                  // Time to Live
    uint8_t protocol{0};             // Next layer protocol (e.g. TCP=6, UDP=17)
    uint16_t checksum{0};
    IPv4Address src_ip{};
    IPv4Address dst_ip{};

    std::string_view options{};      // Zero-copy view of IP options if IHL > 5
    size_t header_length{MIN_HEADER_SIZE}; // Actual header length in bytes (ihl * 4)

    /**
     * @brief Checks if this packet is fragmented.
     */
    bool is_fragmented() const noexcept {
        return flags.more_fragments || (fragment_offset > 0);
    }

    /**
     * @brief Checks if this is the initial fragment of a fragmented sequence.
     */
    bool is_first_fragment() const noexcept {
        return flags.more_fragments && (fragment_offset == 0);
    }

    /**
     * @brief Checks if this is a subsequent fragment (offset > 0) where L4 header is absent.
     */
    bool is_subsequent_fragment() const noexcept {
        return fragment_offset > 0;
    }
};

} // namespace dpi

#endif // DPI_PROTOCOLS_IPV4_H
