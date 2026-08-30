#ifndef DPI_PROTOCOLS_PARSED_PACKET_H
#define DPI_PROTOCOLS_PARSED_PACKET_H

#include "dpi/protocols/ethernet.h"
#include "dpi/protocols/ipv4.h"
#include "dpi/protocols/ipv6.h"
#include "dpi/protocols/protocol_types.h"
#include "dpi/protocols/tcp.h"
#include "dpi/protocols/udp.h"
#include <string_view>

namespace dpi {

/**
 * @brief Canonical representation of a fully decoded packet across layers L2-L4.
 * 
 * Contains parsed metadata for Ethernet, Network (IPv4/IPv6), Transport (TCP/UDP),
 * and provides a zero-copy bounds-checked std::string_view over the L7 payload.
 */
struct ParsedPacket {
    ProtocolErrorCode error_code{ProtocolErrorCode::Success};
    L3Type l3_type{L3Type::None};
    L4Type l4_type{L4Type::None};

    EthernetHeader ethernet{};
    IPv4Header ipv4{};
    IPv6Header ipv6{};
    TcpHeader tcp{};
    UdpHeader udp{};

    std::string_view l7_payload{};    // Zero-copy view of application layer payload

    /**
     * @brief Checks whether the packet was parsed successfully up to its terminal layer.
     */
    bool is_valid() const noexcept {
        return error_code == ProtocolErrorCode::Success;
    }

    bool is_ipv4() const noexcept {
        return l3_type == L3Type::IPv4;
    }

    bool is_ipv6() const noexcept {
        return l3_type == L3Type::IPv6;
    }

    bool is_tcp() const noexcept {
        return l4_type == L4Type::TCP;
    }

    bool is_udp() const noexcept {
        return l4_type == L4Type::UDP;
    }

    bool has_payload() const noexcept {
        return !l7_payload.empty();
    }

    std::string_view error_string() const noexcept {
        return protocol_error_to_string(error_code);
    }
};

} // namespace dpi

#endif // DPI_PROTOCOLS_PARSED_PACKET_H
