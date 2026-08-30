#include "dpi/flow/flow_key.h"
#include <cstring>
#include <sstream>

namespace dpi {

std::string Endpoint::to_string() const {
    std::ostringstream oss;
    if (ip.is_v6()) {
        oss << "[" << ip.to_string() << "]:" << port;
    } else {
        oss << ip.to_string() << ":" << port;
    }
    return oss.str();
}

std::string FlowKey::to_string() const {
    std::ostringstream oss;
    oss << src.to_string() << " <-> " << dst.to_string();
    if (protocol == static_cast<uint8_t>(FlowProtocol::TCP)) {
        oss << " [TCP]";
    } else if (protocol == static_cast<uint8_t>(FlowProtocol::UDP)) {
        oss << " [UDP]";
    } else {
        oss << " [Proto:" << static_cast<int>(protocol) << "]";
    }
    return oss.str();
}

std::pair<FlowKey, FlowDirection> FlowKey::create(const IPAddress& src_ip, uint16_t src_port,
                                                 const IPAddress& dst_ip, uint16_t dst_port,
                                                 uint8_t proto) noexcept {
    Endpoint ep_src{src_ip, src_port};
    Endpoint ep_dst{dst_ip, dst_port};

    if (ep_src < ep_dst) {
        FlowKey key{ep_src, ep_dst, proto};
        return {key, FlowDirection::Forward};
    } else {
        FlowKey key{ep_dst, ep_src, proto};
        return {key, FlowDirection::Reverse};
    }
}

std::pair<FlowKey, FlowDirection> FlowKey::from_packet(const ParsedPacket& packet) noexcept {
    if (!packet.is_valid()) {
        return {FlowKey{}, FlowDirection::Forward};
    }

    IPAddress src_ip;
    IPAddress dst_ip;
    uint8_t proto = 0;

    if (packet.is_ipv4()) {
        src_ip = IPAddress(packet.ipv4.src_ip);
        dst_ip = IPAddress(packet.ipv4.dst_ip);
        proto = packet.ipv4.protocol;
    } else if (packet.is_ipv6()) {
        src_ip = IPAddress(packet.ipv6.src_ip);
        dst_ip = IPAddress(packet.ipv6.dst_ip);
        proto = packet.ipv6.next_header;
    } else {
        return {FlowKey{}, FlowDirection::Forward};
    }

    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    if (packet.is_tcp()) {
        src_port = packet.tcp.src_port;
        dst_port = packet.tcp.dst_port;
    } else if (packet.is_udp()) {
        src_port = packet.udp.src_port;
        dst_port = packet.udp.dst_port;
    } else {
        // Unsupported L4 protocol for flow tracking
        return {FlowKey{}, FlowDirection::Forward};
    }

    return create(src_ip, src_port, dst_ip, dst_port, proto);
}

size_t FlowKeyHasher::operator()(const FlowKey& key) const noexcept {
    uint64_t h = 0xcbf29ce484222325ULL;
    constexpr uint64_t prime = 0x100000001b3ULL;

    auto combine = [&h, prime](uint64_t val) {
        h ^= val;
        h *= prime;
    };

    combine(key.protocol);
    combine(static_cast<uint64_t>(key.src.port) | (static_cast<uint64_t>(key.dst.port) << 16));

    if (key.src.ip.is_v4()) {
        combine(key.src.ip.v4().to_u32());
        combine(key.dst.ip.v4().to_u32());
    } else if (key.src.ip.is_v6()) {
        const auto& b1 = key.src.ip.v6().bytes;
        const auto& b2 = key.dst.ip.v6().bytes;
        uint64_t p1 = 0, p2 = 0, p3 = 0, p4 = 0;
        std::memcpy(&p1, b1.data(), 8);
        std::memcpy(&p2, b1.data() + 8, 8);
        std::memcpy(&p3, b2.data(), 8);
        std::memcpy(&p4, b2.data() + 8, 8);
        combine(p1);
        combine(p2);
        combine(p3);
        combine(p4);
    }

    // 64-bit avalanche mixer for uniform distribution across worker queues
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;

    return static_cast<size_t>(h);
}

} // namespace dpi
