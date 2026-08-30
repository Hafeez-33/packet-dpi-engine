#ifndef DPI_PROTOCOLS_ETHERNET_H
#define DPI_PROTOCOLS_ETHERNET_H

#include "dpi/protocols/protocol_types.h"
#include <cstddef>
#include <cstdint>

namespace dpi {

/**
 * @brief Parsed Ethernet II (DIX) frame header.
 */
struct EthernetHeader {
    static constexpr size_t HEADER_SIZE = 14;

    MacAddress dst_mac{};
    MacAddress src_mac{};
    uint16_t ethertype{0};
};

} // namespace dpi

#endif // DPI_PROTOCOLS_ETHERNET_H
