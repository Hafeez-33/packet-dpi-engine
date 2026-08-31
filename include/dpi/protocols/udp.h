#ifndef DPI_PROTOCOLS_UDP_H
#define DPI_PROTOCOLS_UDP_H

#include "dpi/protocols/protocol_types.h"
#include <cstddef>
#include <cstdint>

namespace dpi {

/**
 * @brief Parsed UDP Header (RFC 768).
 */
struct UdpHeader {
    static constexpr size_t HEADER_SIZE = 8;

    uint16_t src_port{0};
    uint16_t dst_port{0};
    uint16_t length{0};              // Total length in bytes of UDP header + payload
    uint16_t checksum{0};
};

} // namespace dpi

#endif // DPI_PROTOCOLS_UDP_H
