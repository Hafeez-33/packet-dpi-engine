#ifndef DPI_PROTOCOLS_IPV6_H
#define DPI_PROTOCOLS_IPV6_H

#include "dpi/protocols/protocol_types.h"
#include <cstddef>
#include <cstdint>

namespace dpi {

/**
 * @brief Parsed IPv6 Base Header (RFC 8200).
 */
struct IPv6Header {
    static constexpr size_t HEADER_SIZE = 40;

    uint8_t version{6};
    uint8_t traffic_class{0};
    uint32_t flow_label{0};          // 20-bit flow label
    uint16_t payload_length{0};      // Length of payload (bytes following the 40-byte base header)
    uint8_t next_header{0};          // Protocol of next header (e.g. TCP=6, UDP=17)
    uint8_t hop_limit{0};            // Hop limit
    IPv6Address src_ip{};
    IPv6Address dst_ip{};
};

} // namespace dpi

#endif // DPI_PROTOCOLS_IPV6_H
