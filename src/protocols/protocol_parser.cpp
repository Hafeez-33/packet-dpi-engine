#include "dpi/protocols/protocol_parser.h"
#include <algorithm>
#include <cstring>

namespace dpi {

ParsedPacket ProtocolParser::parse(const PacketRecord& record) noexcept {
    if (record.payload.empty()) {
        ParsedPacket p;
        p.error_code = ProtocolErrorCode::EmptyPacket;
        return p;
    }
    return parse(record.payload.data(), record.payload.size());
}

ParsedPacket ProtocolParser::parse(const uint8_t* data, size_t length) noexcept {
    ParsedPacket parsed{};

    if (data == nullptr || length == 0) {
        parsed.error_code = ProtocolErrorCode::EmptyPacket;
        return parsed;
    }

    // 1. Layer-2: Ethernet parsing
    size_t eth_consumed = 0;
    ProtocolErrorCode eth_err = parse_ethernet(data, length, parsed.ethernet, eth_consumed);
    if (eth_err != ProtocolErrorCode::Success) {
        parsed.error_code = eth_err;
        return parsed;
    }

    const uint8_t* l3_data = data + eth_consumed;
    size_t l3_length = length - eth_consumed;

    // 2. Layer-3: Network protocol dispatch
    if (parsed.ethernet.ethertype == ethertype::IPV4) {
        parsed.l3_type = L3Type::IPv4;
        size_t ipv4_consumed = 0;
        ProtocolErrorCode ipv4_err = parse_ipv4(l3_data, l3_length, parsed.ipv4, ipv4_consumed);
        if (ipv4_err != ProtocolErrorCode::Success) {
            parsed.error_code = ipv4_err;
            return parsed;
        }

        const uint8_t* l4_data = l3_data + ipv4_consumed;
        // Total IPv4 total_length includes header + payload; bounds are validated in parse_ipv4
        size_t l4_length = parsed.ipv4.total_length - ipv4_consumed;

        // Check IPv4 fragmentation: non-initial fragments do not contain an L4 header
        if (parsed.ipv4.is_subsequent_fragment()) {
            parsed.l4_type = L4Type::IPv4Fragment;
            parsed.l7_payload = std::string_view(reinterpret_cast<const char*>(l4_data), l4_length);
            parsed.error_code = ProtocolErrorCode::IPv4FragmentedNonInitial;
            return parsed;
        }

        // Layer-4: Transport parsing (TCP / UDP)
        if (parsed.ipv4.protocol == ipproto::TCP) {
            parsed.l4_type = L4Type::TCP;
            size_t tcp_consumed = 0;
            ProtocolErrorCode tcp_err = parse_tcp(l4_data, l4_length, parsed.tcp, tcp_consumed);
            if (tcp_err != ProtocolErrorCode::Success) {
                parsed.error_code = tcp_err;
                return parsed;
            }
            parsed.l7_payload = std::string_view(
                reinterpret_cast<const char*>(l4_data + tcp_consumed),
                l4_length - tcp_consumed
            );
        } else if (parsed.ipv4.protocol == ipproto::UDP) {
            parsed.l4_type = L4Type::UDP;
            size_t udp_consumed = 0;
            ProtocolErrorCode udp_err = parse_udp(l4_data, l4_length, parsed.udp, udp_consumed);
            if (udp_err != ProtocolErrorCode::Success) {
                parsed.error_code = udp_err;
                return parsed;
            }
            parsed.l7_payload = std::string_view(
                reinterpret_cast<const char*>(l4_data + udp_consumed),
                parsed.udp.length - udp_consumed
            );
        } else {
            parsed.l4_type = L4Type::Other;
            parsed.l7_payload = std::string_view(
                reinterpret_cast<const char*>(l4_data),
                l4_length
            );
        }

    } else if (parsed.ethernet.ethertype == ethertype::IPV6) {
        parsed.l3_type = L3Type::IPv6;
        size_t ipv6_consumed = 0;
        ProtocolErrorCode ipv6_err = parse_ipv6(l3_data, l3_length, parsed.ipv6, ipv6_consumed);
        if (ipv6_err != ProtocolErrorCode::Success) {
            parsed.error_code = ipv6_err;
            return parsed;
        }

        const uint8_t* l4_data = l3_data + ipv6_consumed;
        size_t l4_length = parsed.ipv6.payload_length;

        // Layer-4: Transport parsing (direct Next Header TCP / UDP)
        if (parsed.ipv6.next_header == ipproto::TCP) {
            parsed.l4_type = L4Type::TCP;
            size_t tcp_consumed = 0;
            ProtocolErrorCode tcp_err = parse_tcp(l4_data, l4_length, parsed.tcp, tcp_consumed);
            if (tcp_err != ProtocolErrorCode::Success) {
                parsed.error_code = tcp_err;
                return parsed;
            }
            parsed.l7_payload = std::string_view(
                reinterpret_cast<const char*>(l4_data + tcp_consumed),
                l4_length - tcp_consumed
            );
        } else if (parsed.ipv6.next_header == ipproto::UDP) {
            parsed.l4_type = L4Type::UDP;
            size_t udp_consumed = 0;
            ProtocolErrorCode udp_err = parse_udp(l4_data, l4_length, parsed.udp, udp_consumed);
            if (udp_err != ProtocolErrorCode::Success) {
                parsed.error_code = udp_err;
                return parsed;
            }
            parsed.l7_payload = std::string_view(
                reinterpret_cast<const char*>(l4_data + udp_consumed),
                parsed.udp.length - udp_consumed
            );
        } else {
            // Documented limitation: IPv6 extension headers or other L4 protocols
            parsed.l4_type = L4Type::Other;
            parsed.l7_payload = std::string_view(
                reinterpret_cast<const char*>(l4_data),
                l4_length
            );
        }

    } else {
        parsed.l3_type = L3Type::Unsupported;
        parsed.error_code = ProtocolErrorCode::UnsupportedEtherType;
        return parsed;
    }

    parsed.error_code = ProtocolErrorCode::Success;
    return parsed;
}

ProtocolErrorCode ProtocolParser::parse_ethernet(const uint8_t* data, size_t length,
                                                 EthernetHeader& out_eth, size_t& consumed) noexcept {
    if (length < EthernetHeader::HEADER_SIZE) {
        return ProtocolErrorCode::TruncatedEthernet;
    }

    // Destination MAC (bytes 0..5)
    std::memcpy(out_eth.dst_mac.bytes.data(), data, 6);

    // Source MAC (bytes 6..11)
    std::memcpy(out_eth.src_mac.bytes.data(), data + 6, 6);

    // EtherType (bytes 12..13)
    out_eth.ethertype = read_u16_be(data + 12);

    consumed = EthernetHeader::HEADER_SIZE;
    return ProtocolErrorCode::Success;
}

ProtocolErrorCode ProtocolParser::parse_ipv4(const uint8_t* data, size_t length,
                                             IPv4Header& out_ipv4, size_t& consumed) noexcept {
    if (length < IPv4Header::MIN_HEADER_SIZE) {
        return ProtocolErrorCode::TruncatedIPv4;
    }

    uint8_t ver_ihl = read_u8(data);
    out_ipv4.version = static_cast<uint8_t>((ver_ihl >> 4) & 0x0F);
    if (out_ipv4.version != 4) {
        return ProtocolErrorCode::InvalidIPv4Version;
    }

    out_ipv4.ihl = static_cast<uint8_t>(ver_ihl & 0x0F);
    if (out_ipv4.ihl < 5) {
        return ProtocolErrorCode::InvalidIPv4IHL;
    }

    out_ipv4.header_length = static_cast<size_t>(out_ipv4.ihl) * 4;
    if (length < out_ipv4.header_length) {
        return ProtocolErrorCode::TruncatedIPv4;
    }

    uint8_t tos = read_u8(data + 1);
    out_ipv4.dscp = static_cast<uint8_t>((tos >> 2) & 0x3F);
    out_ipv4.ecn  = static_cast<uint8_t>(tos & 0x03);

    out_ipv4.total_length = read_u16_be(data + 2);
    if (out_ipv4.total_length < out_ipv4.header_length) {
        return ProtocolErrorCode::IPv4TotalLengthTooSmall;
    }

    if (length < out_ipv4.total_length) {
        return ProtocolErrorCode::IPv4PacketTooShortForTotalLength;
    }

    out_ipv4.identification = read_u16_be(data + 4);

    uint16_t flags_frag = read_u16_be(data + 6);
    out_ipv4.flags.reserved       = (flags_frag & 0x8000) != 0;
    out_ipv4.flags.dont_fragment  = (flags_frag & 0x4000) != 0;
    out_ipv4.flags.more_fragments = (flags_frag & 0x2000) != 0;
    out_ipv4.fragment_offset      = flags_frag & 0x1FFF;
    out_ipv4.fragment_offset_bytes = static_cast<uint16_t>(out_ipv4.fragment_offset * 8);

    out_ipv4.ttl      = read_u8(data + 8);
    out_ipv4.protocol = read_u8(data + 9);
    out_ipv4.checksum = read_u16_be(data + 10);

    out_ipv4.src_ip = IPv4Address(read_u32_be(data + 12));
    out_ipv4.dst_ip = IPv4Address(read_u32_be(data + 16));

    // Handle IP options
    if (out_ipv4.ihl > 5) {
        size_t options_len = out_ipv4.header_length - IPv4Header::MIN_HEADER_SIZE;
        out_ipv4.options = std::string_view(reinterpret_cast<const char*>(data + 20), options_len);
    } else {
        out_ipv4.options = std::string_view{};
    }

    consumed = out_ipv4.header_length;
    return ProtocolErrorCode::Success;
}

ProtocolErrorCode ProtocolParser::parse_ipv6(const uint8_t* data, size_t length,
                                             IPv6Header& out_ipv6, size_t& consumed) noexcept {
    if (length < IPv6Header::HEADER_SIZE) {
        return ProtocolErrorCode::TruncatedIPv6;
    }

    uint32_t v_tc_fl = read_u32_be(data);
    out_ipv6.version = static_cast<uint8_t>((v_tc_fl >> 28) & 0x0F);
    if (out_ipv6.version != 6) {
        return ProtocolErrorCode::InvalidIPv6Version;
    }

    out_ipv6.traffic_class = static_cast<uint8_t>((v_tc_fl >> 20) & 0xFF);
    out_ipv6.flow_label    = v_tc_fl & 0x000FFFFF;

    out_ipv6.payload_length = read_u16_be(data + 4);
    out_ipv6.next_header    = read_u8(data + 6);
    out_ipv6.hop_limit      = read_u8(data + 7);

    std::memcpy(out_ipv6.src_ip.bytes.data(), data + 8, 16);
    std::memcpy(out_ipv6.dst_ip.bytes.data(), data + 24, 16);

    if ((length - IPv6Header::HEADER_SIZE) < out_ipv6.payload_length) {
        return ProtocolErrorCode::IPv6PacketTooShortForPayload;
    }

    consumed = IPv6Header::HEADER_SIZE;
    return ProtocolErrorCode::Success;
}

ProtocolErrorCode ProtocolParser::parse_tcp(const uint8_t* data, size_t length,
                                            TcpHeader& out_tcp, size_t& consumed) noexcept {
    if (length < TcpHeader::MIN_HEADER_SIZE) {
        return ProtocolErrorCode::TruncatedTCP;
    }

    out_tcp.src_port = read_u16_be(data);
    out_tcp.dst_port = read_u16_be(data + 2);
    out_tcp.seq_num  = read_u32_be(data + 4);
    out_tcp.ack_num  = read_u32_be(data + 8);

    uint8_t offset_byte = read_u8(data + 12);
    out_tcp.data_offset = static_cast<uint8_t>((offset_byte >> 4) & 0x0F);
    if (out_tcp.data_offset < 5) {
        return ProtocolErrorCode::InvalidTcpDataOffset;
    }

    out_tcp.header_length = static_cast<size_t>(out_tcp.data_offset) * 4;
    if (length < out_tcp.header_length) {
        return ProtocolErrorCode::TcpSegmentTooShortForDataOffset;
    }

    uint16_t flags_word = read_u16_be(data + 12);
    out_tcp.flags.cwr = (flags_word & 0x0080) != 0;
    out_tcp.flags.ece = (flags_word & 0x0040) != 0;
    out_tcp.flags.urg = (flags_word & 0x0020) != 0;
    out_tcp.flags.ack = (flags_word & 0x0010) != 0;
    out_tcp.flags.psh = (flags_word & 0x0008) != 0;
    out_tcp.flags.rst = (flags_word & 0x0004) != 0;
    out_tcp.flags.syn = (flags_word & 0x0002) != 0;
    out_tcp.flags.fin = (flags_word & 0x0001) != 0;
    out_tcp.flags.raw = static_cast<uint8_t>(flags_word & 0xFF);

    out_tcp.window_size    = read_u16_be(data + 14);
    out_tcp.checksum       = read_u16_be(data + 16);
    out_tcp.urgent_pointer = read_u16_be(data + 18);

    // Extract TCP options
    if (out_tcp.data_offset > 5) {
        size_t options_len = out_tcp.header_length - TcpHeader::MIN_HEADER_SIZE;
        out_tcp.options = std::string_view(reinterpret_cast<const char*>(data + 20), options_len);
    } else {
        out_tcp.options = std::string_view{};
    }

    consumed = out_tcp.header_length;
    return ProtocolErrorCode::Success;
}

ProtocolErrorCode ProtocolParser::parse_udp(const uint8_t* data, size_t length,
                                            UdpHeader& out_udp, size_t& consumed) noexcept {
    if (length < UdpHeader::HEADER_SIZE) {
        return ProtocolErrorCode::TruncatedUDP;
    }

    out_udp.src_port = read_u16_be(data);
    out_udp.dst_port = read_u16_be(data + 2);
    out_udp.length   = read_u16_be(data + 4);
    out_udp.checksum = read_u16_be(data + 6);

    if (out_udp.length < UdpHeader::HEADER_SIZE) {
        return ProtocolErrorCode::InvalidUdpLength;
    }

    if (length < out_udp.length) {
        return ProtocolErrorCode::UdpPacketTooShortForLength;
    }

    consumed = UdpHeader::HEADER_SIZE;
    return ProtocolErrorCode::Success;
}

} // namespace dpi
