#include "dpi/packet/pcap_reader.h"
#include "dpi/protocols/protocol_parser.h"
#include <cassert>
#include <cstring>
#include <iostream>
#include <sstream>
#include <vector>

using namespace dpi;

// Helper to push big-endian 16-bit
static void push_u16(std::vector<uint8_t>& buf, uint16_t val) {
    buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

// Helper to push big-endian 32-bit
static void push_u32(std::vector<uint8_t>& buf, uint32_t val) {
    buf.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

// Helper to build an Ethernet header
static void append_ethernet(std::vector<uint8_t>& buf,
                            const std::array<uint8_t, 6>& dst_mac,
                            const std::array<uint8_t, 6>& src_mac,
                            uint16_t ethertype) {
    buf.insert(buf.end(), dst_mac.begin(), dst_mac.end());
    buf.insert(buf.end(), src_mac.begin(), src_mac.end());
    push_u16(buf, ethertype);
}

// Helper to build an IPv4 header
static void append_ipv4(std::vector<uint8_t>& buf,
                        uint8_t ihl,
                        uint8_t tos,
                        uint16_t total_length,
                        uint16_t id,
                        bool df, bool mf, uint16_t frag_offset,
                        uint8_t ttl,
                        uint8_t proto,
                        uint16_t checksum,
                        uint32_t src_ip,
                        uint32_t dst_ip,
                        const std::vector<uint8_t>& options = {}) {
    uint8_t ver_ihl = static_cast<uint8_t>((4 << 4) | (ihl & 0x0F));
    buf.push_back(ver_ihl);
    buf.push_back(tos);
    push_u16(buf, total_length);
    push_u16(buf, id);

    uint16_t flags_frag = (frag_offset & 0x1FFF);
    if (df) flags_frag |= 0x4000;
    if (mf) flags_frag |= 0x2000;
    push_u16(buf, flags_frag);

    buf.push_back(ttl);
    buf.push_back(proto);
    push_u16(buf, checksum);
    push_u32(buf, src_ip);
    push_u32(buf, dst_ip);

    if (!options.empty()) {
        buf.insert(buf.end(), options.begin(), options.end());
    }
}

// Helper to build an IPv6 header
static void append_ipv6(std::vector<uint8_t>& buf,
                        uint8_t traffic_class,
                        uint32_t flow_label,
                        uint16_t payload_length,
                        uint8_t next_header,
                        uint8_t hop_limit,
                        const std::array<uint8_t, 16>& src_ip,
                        const std::array<uint8_t, 16>& dst_ip) {
    uint32_t v_tc_fl = (6u << 28) | (static_cast<uint32_t>(traffic_class) << 20) | (flow_label & 0x000FFFFF);
    push_u32(buf, v_tc_fl);
    push_u16(buf, payload_length);
    buf.push_back(next_header);
    buf.push_back(hop_limit);
    buf.insert(buf.end(), src_ip.begin(), src_ip.end());
    buf.insert(buf.end(), dst_ip.begin(), dst_ip.end());
}

// Helper to build a TCP header
static void append_tcp(std::vector<uint8_t>& buf,
                       uint16_t src_port,
                       uint16_t dst_port,
                       uint32_t seq,
                       uint32_t ack,
                       uint8_t data_offset,
                       uint8_t flags_byte,
                       uint16_t window,
                       uint16_t checksum,
                       uint16_t urgent_ptr,
                       const std::vector<uint8_t>& options = {}) {
    push_u16(buf, src_port);
    push_u16(buf, dst_port);
    push_u32(buf, seq);
    push_u32(buf, ack);

    uint16_t offset_flags = (static_cast<uint16_t>(data_offset & 0x0F) << 12) | (flags_byte & 0x01FF);
    push_u16(buf, offset_flags);

    push_u16(buf, window);
    push_u16(buf, checksum);
    push_u16(buf, urgent_ptr);

    if (!options.empty()) {
        buf.insert(buf.end(), options.begin(), options.end());
    }
}

// Helper to build a UDP header
static void append_udp(std::vector<uint8_t>& buf,
                       uint16_t src_port,
                       uint16_t dst_port,
                       uint16_t length,
                       uint16_t checksum) {
    push_u16(buf, src_port);
    push_u16(buf, dst_port);
    push_u16(buf, length);
    push_u16(buf, checksum);
}

// -------------------------------------------------------------
// Test Functions
// -------------------------------------------------------------

void test_valid_ethernet_ipv4_tcp() {
    std::cout << "[TEST] Valid Ethernet + IPv4 + TCP..." << std::endl;
    std::vector<uint8_t> pkt;
    std::array<uint8_t, 6> dst_mac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    std::array<uint8_t, 6> src_mac = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    append_ethernet(pkt, dst_mac, src_mac, ethertype::IPV4);

    std::string payload = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    uint16_t ip_total_len = static_cast<uint16_t>(20 + 20 + payload.size());
    append_ipv4(pkt, 5, 0, ip_total_len, 0x1234, true, false, 0, 64, ipproto::TCP, 0, 0xC0A80164, 0x0A000001); // 192.168.1.100 -> 10.0.0.1

    // TCP flags: SYN (0x02) | ACK (0x10) = 0x12
    append_tcp(pkt, 54321, 80, 100000, 200000, 5, 0x18 /* PSH|ACK */, 65535, 0xABCD, 0);

    pkt.insert(pkt.end(), payload.begin(), payload.end());

    ParsedPacket parsed = ProtocolParser::parse(pkt.data(), pkt.size());
    assert(parsed.is_valid());
    assert(parsed.is_ipv4());
    assert(parsed.is_tcp());
    assert(!parsed.is_udp());

    // Ethernet checks
    assert(parsed.ethernet.dst_mac.to_string() == "00:11:22:33:44:55");
    assert(parsed.ethernet.src_mac.to_string() == "aa:bb:cc:dd:ee:ff");
    assert(parsed.ethernet.ethertype == ethertype::IPV4);

    // IPv4 checks
    assert(parsed.ipv4.version == 4);
    assert(parsed.ipv4.ihl == 5);
    assert(parsed.ipv4.header_length == 20);
    assert(parsed.ipv4.total_length == ip_total_len);
    assert(parsed.ipv4.flags.dont_fragment);
    assert(!parsed.ipv4.flags.more_fragments);
    assert(parsed.ipv4.fragment_offset == 0);
    assert(parsed.ipv4.ttl == 64);
    assert(parsed.ipv4.protocol == ipproto::TCP);
    assert(parsed.ipv4.src_ip.to_string() == "192.168.1.100");
    assert(parsed.ipv4.dst_ip.to_string() == "10.0.0.1");
    assert(parsed.ipv4.options.empty());

    // TCP checks
    assert(parsed.tcp.src_port == 54321);
    assert(parsed.tcp.dst_port == 80);
    assert(parsed.tcp.seq_num == 100000);
    assert(parsed.tcp.ack_num == 200000);
    assert(parsed.tcp.data_offset == 5);
    assert(parsed.tcp.header_length == 20);
    assert(parsed.tcp.flags.psh);
    assert(parsed.tcp.flags.ack);
    assert(!parsed.tcp.flags.syn);
    assert(!parsed.tcp.flags.fin);
    assert(parsed.tcp.window_size == 65535);
    assert(parsed.tcp.options.empty());

    // Payload checks
    assert(parsed.has_payload());
    assert(parsed.l7_payload == payload);
}

void test_valid_ethernet_ipv4_udp() {
    std::cout << "[TEST] Valid Ethernet + IPv4 + UDP..." << std::endl;
    std::vector<uint8_t> pkt;
    std::array<uint8_t, 6> dst_mac = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    std::array<uint8_t, 6> src_mac = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc};
    append_ethernet(pkt, dst_mac, src_mac, ethertype::IPV4);

    std::string payload = "Hello UDP World!";
    uint16_t udp_len = static_cast<uint16_t>(8 + payload.size());
    uint16_t ip_total_len = static_cast<uint16_t>(20 + udp_len);
    append_ipv4(pkt, 5, 0, ip_total_len, 0x5678, false, false, 0, 128, ipproto::UDP, 0, 0x0A000005, 0x08080808); // 10.0.0.5 -> 8.8.8.8

    append_udp(pkt, 12345, 53, udp_len, 0x1234);
    pkt.insert(pkt.end(), payload.begin(), payload.end());

    ParsedPacket parsed = ProtocolParser::parse(pkt.data(), pkt.size());
    assert(parsed.is_valid());
    assert(parsed.is_ipv4());
    assert(parsed.is_udp());
    assert(!parsed.is_tcp());

    assert(parsed.ipv4.src_ip.to_string() == "10.0.0.5");
    assert(parsed.ipv4.dst_ip.to_string() == "8.8.8.8");
    assert(parsed.udp.src_port == 12345);
    assert(parsed.udp.dst_port == 53);
    assert(parsed.udp.length == udp_len);
    assert(parsed.udp.checksum == 0x1234);

    assert(parsed.has_payload());
    assert(parsed.l7_payload == payload);
}

void test_ipv4_with_options() {
    std::cout << "[TEST] IPv4 with options (IHL > 5)..." << std::endl;
    std::vector<uint8_t> pkt;
    std::array<uint8_t, 6> mac = {0, 0, 0, 0, 0, 0};
    append_ethernet(pkt, mac, mac, ethertype::IPV4);

    std::vector<uint8_t> ip_options = {0x01, 0x01, 0x01, 0x01}; // 4 bytes of NOP options -> IHL = 6
    std::string payload = "DataAfterOptions";
    uint16_t udp_len = static_cast<uint16_t>(8 + payload.size());
    uint16_t ip_total_len = static_cast<uint16_t>(24 + udp_len);

    append_ipv4(pkt, 6, 0, ip_total_len, 0x1111, false, false, 0, 64, ipproto::UDP, 0, 0x7F000001, 0x7F000001, ip_options);
    append_udp(pkt, 5000, 6000, udp_len, 0);
    pkt.insert(pkt.end(), payload.begin(), payload.end());

    ParsedPacket parsed = ProtocolParser::parse(pkt.data(), pkt.size());
    assert(parsed.is_valid());
    assert(parsed.ipv4.ihl == 6);
    assert(parsed.ipv4.header_length == 24);
    assert(parsed.ipv4.options.size() == 4);
    assert(static_cast<uint8_t>(parsed.ipv4.options[0]) == 0x01);
    assert(parsed.is_udp());
    assert(parsed.udp.src_port == 5000);
    assert(parsed.udp.dst_port == 6000);
    assert(parsed.l7_payload == payload);
}

void test_valid_ipv6_tcp_and_udp() {
    std::cout << "[TEST] Valid IPv6 + TCP and IPv6 + UDP..." << std::endl;
    // 1. IPv6 TCP
    {
        std::vector<uint8_t> pkt;
        std::array<uint8_t, 6> mac = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
        append_ethernet(pkt, mac, mac, ethertype::IPV6);

        std::array<uint8_t, 16> src_ip = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        std::array<uint8_t, 16> dst_ip = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};

        std::string payload = "IPv6 TCP Payload";
        uint16_t ipv6_payload_len = static_cast<uint16_t>(20 + payload.size());
        append_ipv6(pkt, 0x10, 0x000ABCDE, ipv6_payload_len, ipproto::TCP, 128, src_ip, dst_ip);
        append_tcp(pkt, 443, 61234, 500, 600, 5, 0x02 /* SYN */, 32768, 0, 0);
        pkt.insert(pkt.end(), payload.begin(), payload.end());

        ParsedPacket parsed = ProtocolParser::parse(pkt.data(), pkt.size());
        assert(parsed.is_valid());
        assert(parsed.is_ipv6());
        assert(parsed.is_tcp());
        assert(parsed.ipv6.version == 6);
        assert(parsed.ipv6.traffic_class == 0x10);
        assert(parsed.ipv6.flow_label == 0x000ABCDE);
        assert(parsed.ipv6.payload_length == ipv6_payload_len);
        assert(parsed.ipv6.next_header == ipproto::TCP);
        assert(parsed.ipv6.hop_limit == 128);
        assert(parsed.ipv6.src_ip.to_string() == "2001:db8:0:0:0:0:0:1");
        assert(parsed.ipv6.dst_ip.to_string() == "2001:db8:0:0:0:0:0:2");
        assert(parsed.tcp.src_port == 443);
        assert(parsed.tcp.dst_port == 61234);
        assert(parsed.tcp.flags.syn);
        assert(parsed.l7_payload == payload);
    }

    // 2. IPv6 UDP
    {
        std::vector<uint8_t> pkt;
        std::array<uint8_t, 6> mac = {0, 0, 0, 0, 0, 0};
        append_ethernet(pkt, mac, mac, ethertype::IPV6);

        std::array<uint8_t, 16> src_ip = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        std::array<uint8_t, 16> dst_ip = {0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

        std::string payload = "IPv6 UDP Payload";
        uint16_t udp_len = static_cast<uint16_t>(8 + payload.size());
        append_ipv6(pkt, 0, 0, udp_len, ipproto::UDP, 64, src_ip, dst_ip);
        append_udp(pkt, 5353, 5353, udp_len, 0);
        pkt.insert(pkt.end(), payload.begin(), payload.end());

        ParsedPacket parsed = ProtocolParser::parse(pkt.data(), pkt.size());
        assert(parsed.is_valid());
        assert(parsed.is_ipv6());
        assert(parsed.is_udp());
        assert(parsed.udp.src_port == 5353);
        assert(parsed.udp.dst_port == 5353);
        assert(parsed.l7_payload == payload);
    }
}

void test_tcp_options() {
    std::cout << "[TEST] TCP with options (Data Offset > 5)..." << std::endl;
    std::vector<uint8_t> pkt;
    std::array<uint8_t, 6> mac = {0, 0, 0, 0, 0, 0};
    append_ethernet(pkt, mac, mac, ethertype::IPV4);

    // 12 bytes of TCP options: MSS (4 bytes) + NOP NOP + Window Scale (3 bytes) + SACK-Permitted (2 bytes) + NOP
    std::vector<uint8_t> tcp_options = {
        0x02, 0x04, 0x05, 0xb4, // MSS = 1460
        0x01, 0x03, 0x03, 0x07, // WS = 7
        0x04, 0x02, 0x01, 0x00  // SACK-Permitted, NOP, End
    };
    std::string payload = "AppPayloadAfterTcpOptions";
    uint16_t ip_total_len = static_cast<uint16_t>(20 + 32 + payload.size());

    append_ipv4(pkt, 5, 0, ip_total_len, 0x4321, true, false, 0, 64, ipproto::TCP, 0, 0x0A000001, 0x0A000002);
    append_tcp(pkt, 1234, 4321, 10, 20, 8 /* data offset = 32 bytes */, 0x10, 1024, 0, 0, tcp_options);
    pkt.insert(pkt.end(), payload.begin(), payload.end());

    ParsedPacket parsed = ProtocolParser::parse(pkt.data(), pkt.size());
    assert(parsed.is_valid());
    assert(parsed.tcp.data_offset == 8);
    assert(parsed.tcp.header_length == 32);
    assert(parsed.tcp.options.size() == 12);
    assert(parsed.l7_payload == payload);
}

void test_ipv4_fragmentation() {
    std::cout << "[TEST] IPv4 Fragmentation handling..." << std::endl;
    std::array<uint8_t, 6> mac = {0, 0, 0, 0, 0, 0};

    // 1. Initial fragment: MF=1, offset=0, protocol=TCP -> TCP parsed
    {
        std::vector<uint8_t> pkt;
        append_ethernet(pkt, mac, mac, ethertype::IPV4);
        std::string payload = "FragmentOneL7Data";
        uint16_t ip_total_len = static_cast<uint16_t>(20 + 20 + payload.size());
        append_ipv4(pkt, 5, 0, ip_total_len, 0x9999, false, true /* MF */, 0 /* offset */, 64, ipproto::TCP, 0, 0x0A000001, 0x0A000002);
        append_tcp(pkt, 8080, 9090, 1, 1, 5, 0x18, 4096, 0, 0);
        pkt.insert(pkt.end(), payload.begin(), payload.end());

        ParsedPacket parsed = ProtocolParser::parse(pkt.data(), pkt.size());
        assert(parsed.is_valid());
        assert(parsed.ipv4.is_fragmented());
        assert(parsed.ipv4.is_first_fragment());
        assert(!parsed.ipv4.is_subsequent_fragment());
        assert(parsed.is_tcp());
        assert(parsed.l7_payload == payload);
    }

    // 2. Subsequent non-initial fragment: MF=1, offset=185 (1480 bytes) -> Not blindly parsing TCP
    {
        std::vector<uint8_t> pkt;
        append_ethernet(pkt, mac, mac, ethertype::IPV4);
        std::string raw_frag_data = "ThisIsRawFragmentPayloadWithoutL4Header";
        uint16_t ip_total_len = static_cast<uint16_t>(20 + raw_frag_data.size());
        append_ipv4(pkt, 5, 0, ip_total_len, 0x9999, false, true /* MF */, 185 /* offset */, 64, ipproto::TCP, 0, 0x0A000001, 0x0A000002);
        pkt.insert(pkt.end(), raw_frag_data.begin(), raw_frag_data.end());

        ParsedPacket parsed = ProtocolParser::parse(pkt.data(), pkt.size());
        assert(parsed.error_code == ProtocolErrorCode::IPv4FragmentedNonInitial);
        assert(parsed.l4_type == L4Type::IPv4Fragment);
        assert(parsed.ipv4.is_fragmented());
        assert(parsed.ipv4.is_subsequent_fragment());
        assert(parsed.ipv4.fragment_offset == 185);
        assert(parsed.ipv4.fragment_offset_bytes == 185 * 8);
        assert(parsed.l7_payload == raw_frag_data);
    }

    // 3. Final fragment: MF=0, offset=370 -> Not blindly parsing TCP
    {
        std::vector<uint8_t> pkt;
        append_ethernet(pkt, mac, mac, ethertype::IPV4);
        std::string raw_frag_data = "FinalFragmentPayload";
        uint16_t ip_total_len = static_cast<uint16_t>(20 + raw_frag_data.size());
        append_ipv4(pkt, 5, 0, ip_total_len, 0x9999, false, false /* MF=0 */, 370 /* offset > 0 */, 64, ipproto::TCP, 0, 0x0A000001, 0x0A000002);
        pkt.insert(pkt.end(), raw_frag_data.begin(), raw_frag_data.end());

        ParsedPacket parsed = ProtocolParser::parse(pkt.data(), pkt.size());
        assert(parsed.error_code == ProtocolErrorCode::IPv4FragmentedNonInitial);
        assert(parsed.l4_type == L4Type::IPv4Fragment);
        assert(parsed.ipv4.is_fragmented());
        assert(parsed.ipv4.is_subsequent_fragment());
        assert(parsed.ipv4.fragment_offset == 370);
        assert(parsed.l7_payload == raw_frag_data);
    }
}

void test_error_handling_and_truncation() {
    std::cout << "[TEST] Error handling, truncation, and bounds checking..." << std::endl;
    std::array<uint8_t, 6> mac = {0, 0, 0, 0, 0, 0};

    // 1. Empty buffer
    {
        ParsedPacket p = ProtocolParser::parse(nullptr, 0);
        assert(p.error_code == ProtocolErrorCode::EmptyPacket);
        assert(!p.is_valid());
    }

    // 2. Truncated Ethernet (< 14 bytes)
    {
        uint8_t short_eth[10] = {0};
        ParsedPacket p = ProtocolParser::parse(short_eth, sizeof(short_eth));
        assert(p.error_code == ProtocolErrorCode::TruncatedEthernet);
    }

    // 3. Unsupported EtherType (e.g. ARP 0x0806)
    {
        std::vector<uint8_t> pkt;
        append_ethernet(pkt, mac, mac, ethertype::ARP);
        pkt.resize(pkt.size() + 28); // dummy ARP body
        ParsedPacket p = ProtocolParser::parse(pkt.data(), pkt.size());
        assert(p.error_code == ProtocolErrorCode::UnsupportedEtherType);
        assert(p.l3_type == L3Type::Unsupported);
    }

    // 4. Truncated IPv4 header (< 20 bytes)
    {
        std::vector<uint8_t> pkt;
        append_ethernet(pkt, mac, mac, ethertype::IPV4);
        pkt.push_back(0x45); // only 1 byte of IPv4
        ParsedPacket p = ProtocolParser::parse(pkt.data(), pkt.size());
        assert(p.error_code == ProtocolErrorCode::TruncatedIPv4);
    }

    // 5. Invalid IPv4 version (e.g. version 5)
    {
        std::vector<uint8_t> pkt;
        append_ethernet(pkt, mac, mac, ethertype::IPV4);
        pkt.resize(pkt.size() + 20, 0);
        pkt[14] = 0x55; // Version 5, IHL 5
        ParsedPacket p = ProtocolParser::parse(pkt.data(), pkt.size());
        assert(p.error_code == ProtocolErrorCode::InvalidIPv4Version);
    }

    // 6. Invalid IPv4 IHL (< 5)
    {
        std::vector<uint8_t> pkt;
        append_ethernet(pkt, mac, mac, ethertype::IPV4);
        pkt.resize(pkt.size() + 20, 0);
        pkt[14] = 0x44; // Version 4, IHL 4 (invalid)
        ParsedPacket p = ProtocolParser::parse(pkt.data(), pkt.size());
        assert(p.error_code == ProtocolErrorCode::InvalidIPv4IHL);
    }

    // 7. IPv4 total length too small (< IHL*4)
    {
        std::vector<uint8_t> pkt;
        append_ethernet(pkt, mac, mac, ethertype::IPV4);
        append_ipv4(pkt, 5, 0, 10 /* total length < 20 */, 1, false, false, 0, 64, ipproto::TCP, 0, 0, 0);
        ParsedPacket p = ProtocolParser::parse(pkt.data(), pkt.size());
        assert(p.error_code == ProtocolErrorCode::IPv4TotalLengthTooSmall);
    }

    // 8. IPv4 packet shorter than total length
    {
        std::vector<uint8_t> pkt;
        append_ethernet(pkt, mac, mac, ethertype::IPV4);
        append_ipv4(pkt, 5, 0, 100 /* claimed 100 bytes */, 1, false, false, 0, 64, ipproto::TCP, 0, 0, 0);
        // buffer has only 14 + 20 = 34 bytes
        ParsedPacket p = ProtocolParser::parse(pkt.data(), pkt.size());
        assert(p.error_code == ProtocolErrorCode::IPv4PacketTooShortForTotalLength);
    }

    // 9. Truncated IPv6 header (< 40 bytes)
    {
        std::vector<uint8_t> pkt;
        append_ethernet(pkt, mac, mac, ethertype::IPV6);
        pkt.resize(pkt.size() + 20, 0); // only 20 bytes of IPv6
        ParsedPacket p = ProtocolParser::parse(pkt.data(), pkt.size());
        assert(p.error_code == ProtocolErrorCode::TruncatedIPv6);
    }

    // 10. Invalid IPv6 version
    {
        std::vector<uint8_t> pkt;
        append_ethernet(pkt, mac, mac, ethertype::IPV6);
        pkt.resize(pkt.size() + 40, 0);
        pkt[14] = 0x40; // Version 4 instead of 6
        ParsedPacket p = ProtocolParser::parse(pkt.data(), pkt.size());
        assert(p.error_code == ProtocolErrorCode::InvalidIPv6Version);
    }

    // 11. IPv6 packet shorter than payload length
    {
        std::vector<uint8_t> pkt;
        append_ethernet(pkt, mac, mac, ethertype::IPV6);
        std::array<uint8_t, 16> addr = {0};
        append_ipv6(pkt, 0, 0, 200 /* claimed 200 bytes */, ipproto::TCP, 64, addr, addr);
        // Only 14 + 40 = 54 bytes in buffer
        ParsedPacket p = ProtocolParser::parse(pkt.data(), pkt.size());
        assert(p.error_code == ProtocolErrorCode::IPv6PacketTooShortForPayload);
    }

    // 12. Truncated TCP (< 20 bytes)
    {
        std::vector<uint8_t> pkt;
        append_ethernet(pkt, mac, mac, ethertype::IPV4);
        append_ipv4(pkt, 5, 0, 30 /* 20 byte IP + 10 byte TCP */, 1, false, false, 0, 64, ipproto::TCP, 0, 0, 0);
        pkt.resize(pkt.size() + 10, 0);
        ParsedPacket p = ProtocolParser::parse(pkt.data(), pkt.size());
        assert(p.error_code == ProtocolErrorCode::TruncatedTCP);
    }

    // 13. Invalid TCP Data Offset (< 5)
    {
        std::vector<uint8_t> pkt;
        append_ethernet(pkt, mac, mac, ethertype::IPV4);
        append_ipv4(pkt, 5, 0, 40, 1, false, false, 0, 64, ipproto::TCP, 0, 0, 0);
        append_tcp(pkt, 80, 80, 1, 1, 4 /* data offset = 4 < 5 */, 0, 1000, 0, 0);
        ParsedPacket p = ProtocolParser::parse(pkt.data(), pkt.size());
        assert(p.error_code == ProtocolErrorCode::InvalidTcpDataOffset);
    }

    // 14. TCP Segment too short for Data Offset
    {
        std::vector<uint8_t> pkt;
        append_ethernet(pkt, mac, mac, ethertype::IPV4);
        append_ipv4(pkt, 5, 0, 40 /* 20 IP + 20 TCP buffer */, 1, false, false, 0, 64, ipproto::TCP, 0, 0, 0);
        append_tcp(pkt, 80, 80, 1, 1, 8 /* claims 32 bytes */, 0, 1000, 0, 0);
        ParsedPacket p = ProtocolParser::parse(pkt.data(), pkt.size());
        assert(p.error_code == ProtocolErrorCode::TcpSegmentTooShortForDataOffset);
    }

    // 15. Truncated UDP (< 8 bytes)
    {
        std::vector<uint8_t> pkt;
        append_ethernet(pkt, mac, mac, ethertype::IPV4);
        append_ipv4(pkt, 5, 0, 24 /* 20 IP + 4 UDP */, 1, false, false, 0, 64, ipproto::UDP, 0, 0, 0);
        pkt.resize(pkt.size() + 4, 0);
        ParsedPacket p = ProtocolParser::parse(pkt.data(), pkt.size());
        assert(p.error_code == ProtocolErrorCode::TruncatedUDP);
    }

    // 16. Invalid UDP length (< 8)
    {
        std::vector<uint8_t> pkt;
        append_ethernet(pkt, mac, mac, ethertype::IPV4);
        append_ipv4(pkt, 5, 0, 28, 1, false, false, 0, 64, ipproto::UDP, 0, 0, 0);
        append_udp(pkt, 53, 53, 6 /* length = 6 < 8 */, 0);
        ParsedPacket p = ProtocolParser::parse(pkt.data(), pkt.size());
        assert(p.error_code == ProtocolErrorCode::InvalidUdpLength);
    }

    // 17. UDP Packet too short for length field
    {
        std::vector<uint8_t> pkt;
        append_ethernet(pkt, mac, mac, ethertype::IPV4);
        append_ipv4(pkt, 5, 0, 28, 1, false, false, 0, 64, ipproto::UDP, 0, 0, 0);
        append_udp(pkt, 53, 53, 50 /* claims 50 bytes */, 0);
        ParsedPacket p = ProtocolParser::parse(pkt.data(), pkt.size());
        assert(p.error_code == ProtocolErrorCode::UdpPacketTooShortForLength);
    }
}

// -------------------------------------------------------------
// Integration Test: PCAP Reader -> Protocol Parser
// -------------------------------------------------------------

static void write_u32_le(std::ostream& os, uint32_t val) {
    os.write(reinterpret_cast<const char*>(&val), sizeof(val));
}

static void write_u16_le(std::ostream& os, uint16_t val) {
    os.write(reinterpret_cast<const char*>(&val), sizeof(val));
}

void test_integration_pcap_reader_to_protocol_parser() {
    std::cout << "[TEST] Integration: PcapReader stream -> ProtocolParser..." << std::endl;
    std::stringstream pcap_stream(std::ios::in | std::ios::out | std::ios::binary);

    // 1. Write Global Header (24 bytes)
    write_u32_le(pcap_stream, pcap_magic::MICROSEC_NATIVE);
    write_u16_le(pcap_stream, 2);
    write_u16_le(pcap_stream, 4);
    write_u32_le(pcap_stream, 0);
    write_u32_le(pcap_stream, 0);
    write_u32_le(pcap_stream, 65535);
    write_u32_le(pcap_stream, 1); // DLT_EN10MB

    // 2. Build Packet 1: IPv4 TCP (HTTP GET)
    std::vector<uint8_t> pkt1;
    std::array<uint8_t, 6> mac1 = {0x00, 0x50, 0x56, 0xc0, 0x00, 0x01};
    std::array<uint8_t, 6> mac2 = {0x00, 0x50, 0x56, 0xc0, 0x00, 0x02};
    append_ethernet(pkt1, mac1, mac2, ethertype::IPV4);
    std::string http_payload = "GET /api/v1/metrics HTTP/1.1\r\nHost: api.local\r\n\r\n";
    uint16_t ip1_len = static_cast<uint16_t>(20 + 20 + http_payload.size());
    append_ipv4(pkt1, 5, 0, ip1_len, 101, true, false, 0, 64, ipproto::TCP, 0, 0x0A000064, 0x0A0000C8); // 10.0.0.100 -> 10.0.0.200
    append_tcp(pkt1, 50123, 80, 1000, 2000, 5, 0x18, 32768, 0, 0);
    pkt1.insert(pkt1.end(), http_payload.begin(), http_payload.end());

    // Write Packet 1 Header + Data
    write_u32_le(pcap_stream, 1600000000); // ts_sec
    write_u32_le(pcap_stream, 100);        // ts_usec
    write_u32_le(pcap_stream, static_cast<uint32_t>(pkt1.size()));
    write_u32_le(pcap_stream, static_cast<uint32_t>(pkt1.size()));
    pcap_stream.write(reinterpret_cast<const char*>(pkt1.data()), pkt1.size());

    // 3. Build Packet 2: IPv4 UDP (DNS Query)
    std::vector<uint8_t> pkt2;
    append_ethernet(pkt2, mac2, mac1, ethertype::IPV4);
    std::string dns_payload = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";
    uint16_t udp_len = static_cast<uint16_t>(8 + dns_payload.size());
    uint16_t ip2_len = static_cast<uint16_t>(20 + udp_len);
    append_ipv4(pkt2, 5, 0, ip2_len, 102, false, false, 0, 64, ipproto::UDP, 0, 0x0A000064, 0x08080808);
    append_udp(pkt2, 61234, 53, udp_len, 0);
    pkt2.insert(pkt2.end(), dns_payload.begin(), dns_payload.end());

    // Write Packet 2 Header + Data
    write_u32_le(pcap_stream, 1600000001);
    write_u32_le(pcap_stream, 200);
    write_u32_le(pcap_stream, static_cast<uint32_t>(pkt2.size()));
    write_u32_le(pcap_stream, static_cast<uint32_t>(pkt2.size()));
    pcap_stream.write(reinterpret_cast<const char*>(pkt2.data()), pkt2.size());

    // 4. Ingest via PcapReader and parse via ProtocolParser
    PcapReader reader;
    PcapErrorCode open_err = reader.open(pcap_stream);
    assert(open_err == PcapErrorCode::Success);

    // Read Packet 1
    PacketRecord rec1;
    assert(reader.read_next_packet(rec1) == PcapErrorCode::Success);
    ParsedPacket parsed1 = ProtocolParser::parse(rec1);
    assert(parsed1.is_valid());
    assert(parsed1.is_ipv4());
    assert(parsed1.is_tcp());
    assert(parsed1.ipv4.src_ip.to_string() == "10.0.0.100");
    assert(parsed1.ipv4.dst_ip.to_string() == "10.0.0.200");
    assert(parsed1.tcp.src_port == 50123);
    assert(parsed1.tcp.dst_port == 80);
    assert(parsed1.l7_payload == http_payload);

    // Read Packet 2
    PacketRecord rec2;
    assert(reader.read_next_packet(rec2) == PcapErrorCode::Success);
    ParsedPacket parsed2 = ProtocolParser::parse(rec2);
    assert(parsed2.is_valid());
    assert(parsed2.is_ipv4());
    assert(parsed2.is_udp());
    assert(parsed2.ipv4.src_ip.to_string() == "10.0.0.100");
    assert(parsed2.ipv4.dst_ip.to_string() == "8.8.8.8");
    assert(parsed2.udp.src_port == 61234);
    assert(parsed2.udp.dst_port == 53);
    assert(parsed2.l7_payload == dns_payload);

    // End of file
    PacketRecord rec3;
    assert(reader.read_next_packet(rec3) == PcapErrorCode::EndOfFile);
}

int main() {
    std::cout << "========================================\n";
    std::cout << "  Stage 2 Protocol Parser Test Suite   \n";
    std::cout << "========================================\n";

    test_valid_ethernet_ipv4_tcp();
    test_valid_ethernet_ipv4_udp();
    test_ipv4_with_options();
    test_valid_ipv6_tcp_and_udp();
    test_tcp_options();
    test_ipv4_fragmentation();
    test_error_handling_and_truncation();
    test_integration_pcap_reader_to_protocol_parser();

    std::cout << "All Stage 2 Protocol Parser tests PASSED!\n";
    return 0;
}
