#ifndef DPI_FLOW_FLOW_KEY_H
#define DPI_FLOW_FLOW_KEY_H

#include "dpi/flow/flow_types.h"
#include "dpi/flow/ip_address.h"
#include "dpi/protocols/parsed_packet.h"
#include <functional>
#include <string>
#include <utility>

namespace dpi {

/**
 * @brief Represents a network endpoint (IP address and transport port).
 */
struct Endpoint {
    IPAddress ip{};
    uint16_t port{0};

    bool operator==(const Endpoint& other) const noexcept {
        return port == other.port && ip == other.ip;
    }

    bool operator!=(const Endpoint& other) const noexcept {
        return !(*this == other);
    }

    bool operator<(const Endpoint& other) const noexcept {
        if (ip < other.ip) return true;
        if (other.ip < ip) return false;
        return port < other.port;
    }

    std::string to_string() const;
};

/**
 * @brief Canonical 5-tuple key for bidirectional flow identification.
 * 
 * Normalizes (src, dst) endpoints such that packets in both directions map
 * to the exact same FlowKey.
 */
struct FlowKey {
    Endpoint src{};      // Canonical lower endpoint
    Endpoint dst{};      // Canonical higher endpoint
    uint8_t protocol{0}; // Transport protocol (TCP=6, UDP=17)

    bool operator==(const FlowKey& other) const noexcept {
        return protocol == other.protocol && src == other.src && dst == other.dst;
    }

    bool operator!=(const FlowKey& other) const noexcept {
        return !(*this == other);
    }

    bool operator<(const FlowKey& other) const noexcept {
        if (protocol != other.protocol) return protocol < other.protocol;
        if (src < other.src) return true;
        if (other.src < src) return false;
        return dst < other.dst;
    }

    std::string to_string() const;

    /**
     * @brief Creates a canonical FlowKey and relative FlowDirection from raw endpoint parameters.
     */
    static std::pair<FlowKey, FlowDirection> create(const IPAddress& src_ip, uint16_t src_port,
                                                   const IPAddress& dst_ip, uint16_t dst_port,
                                                   uint8_t proto) noexcept;

    /**
     * @brief Extracts and normalizes the FlowKey and relative FlowDirection from a ParsedPacket.
     * @return Pair of FlowKey and FlowDirection. If packet is not a valid IPv4/IPv6 TCP/UDP packet,
     *         returns an invalid empty key.
     */
    static std::pair<FlowKey, FlowDirection> from_packet(const ParsedPacket& packet) noexcept;
};

/**
 * @brief Fast 64-bit FNV-1a / bit-mixing hash functor for FlowKey.
 */
struct FlowKeyHasher {
    size_t operator()(const FlowKey& key) const noexcept;
};

} // namespace dpi

// Specialization of std::hash for dpi::FlowKey
namespace std {
template <>
struct hash<dpi::FlowKey> {
    size_t operator()(const dpi::FlowKey& key) const noexcept {
        return dpi::FlowKeyHasher{}(key);
    }
};
} // namespace std

#endif // DPI_FLOW_FLOW_KEY_H
