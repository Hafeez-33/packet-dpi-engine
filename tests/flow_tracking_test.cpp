#include "dpi/flow/flow_table.h"
#include "dpi/packet/pcap_reader.h"
#include "dpi/protocols/protocol_parser.h"
#include <cassert>
#include <iostream>
#include <sstream>
#include <vector>

using namespace dpi;

// Helpers to construct packets
static void push_u16(std::vector<uint8_t>& buf, uint16_t val) {
    buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

static void push_u32(std::vector<uint8_t>& buf, uint32_t val) {
    buf.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

static void append_ethernet(std::vector<uint8_t>& buf, uint16_t ethertype) {
    for (int i = 0; i < 12; ++i) buf.push_back(0); // 6 bytes dst, 6 bytes src
    push_u16(buf, ethertype);
}

static void append_ipv4(std::vector<uint8_t>& buf, uint16_t total_len, uint8_t proto,
                        uint32_t src_ip, uint32_t dst_ip) {
    buf.push_back(0x45); // Version 4, IHL 5
    buf.push_back(0x00); // TOS
    push_u16(buf, total_len);
    push_u16(buf, 0x1234); // ID
    push_u16(buf, 0x4000); // Flags (DF)
    buf.push_back(64);     // TTL
    buf.push_back(proto);
    push_u16(buf, 0);      // Checksum
    push_u32(buf, src_ip);
    push_u32(buf, dst_ip);
}

static void append_ipv6(std::vector<uint8_t>& buf, uint16_t payload_len, uint8_t next_hdr,
                        const std::array<uint8_t, 16>& src_ip,
                        const std::array<uint8_t, 16>& dst_ip) {
    push_u32(buf, 6u << 28);
    push_u16(buf, payload_len);
    buf.push_back(next_hdr);
    buf.push_back(64);
    buf.insert(buf.end(), src_ip.begin(), src_ip.end());
    buf.insert(buf.end(), dst_ip.begin(), dst_ip.end());
}

static void append_tcp(std::vector<uint8_t>& buf, uint16_t src_port, uint16_t dst_port,
                       uint32_t seq, uint32_t ack, uint8_t flags_byte) {
    push_u16(buf, src_port);
    push_u16(buf, dst_port);
    push_u32(buf, seq);
    push_u32(buf, ack);
    push_u16(buf, (5u << 12) | flags_byte); // Data offset 5
    push_u16(buf, 65535);                   // Window
    push_u16(buf, 0);                       // Checksum
    push_u16(buf, 0);                       // Urgent pointer
}

static void append_udp(std::vector<uint8_t>& buf, uint16_t src_port, uint16_t dst_port,
                       uint16_t len) {
    push_u16(buf, src_port);
    push_u16(buf, dst_port);
    push_u16(buf, len);
    push_u16(buf, 0);
}

// -------------------------------------------------------------
// Test Functions
// -------------------------------------------------------------

void test_timestamp_normalization() {
    std::cout << "[TEST] Timestamp normalization..." << std::endl;
    // Microsecond mode
    uint64_t ts1 = normalize_timestamp_us(100, 500000, false);
    assert(ts1 == 100500000ULL);

    // Nanosecond mode: 500,000,000 ns = 500,000 us
    uint64_t ts2 = normalize_timestamp_us(100, 500000000, true);
    assert(ts2 == 100500000ULL);
}

void test_ipv4_canonical_normalization() {
    std::cout << "[TEST] IPv4 Canonical 5-Tuple Normalization..." << std::endl;
    IPv4Address ip_client(192, 168, 1, 100);
    IPv4Address ip_server(10, 0, 0, 1);
    uint16_t port_client = 54321;
    uint16_t port_server = 80;

    auto [key1, dir1] = FlowKey::create(IPAddress(ip_client), port_client,
                                        IPAddress(ip_server), port_server, 6);
    auto [key2, dir2] = FlowKey::create(IPAddress(ip_server), port_server,
                                        IPAddress(ip_client), port_client, 6);

    assert(key1 == key2);
    assert(dir1 != dir2);
    assert(std::hash<FlowKey>{}(key1) == std::hash<FlowKey>{}(key2));
    assert(!key1.to_string().empty());
}

void test_ipv6_canonical_normalization() {
    std::cout << "[TEST] IPv6 Canonical 5-Tuple Normalization..." << std::endl;
    std::array<uint8_t, 16> addr1 = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    std::array<uint8_t, 16> addr2 = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};

    auto [key1, dir1] = FlowKey::create(IPAddress(IPv6Address(addr1)), 50000,
                                        IPAddress(IPv6Address(addr2)), 443, 6);
    auto [key2, dir2] = FlowKey::create(IPAddress(IPv6Address(addr2)), 443,
                                        IPAddress(IPv6Address(addr1)), 50000, 6);

    assert(key1 == key2);
    assert(dir1 != dir2);
    assert(std::hash<FlowKey>{}(key1) == std::hash<FlowKey>{}(key2));

    // Test IPv6 packet ingestion in FlowTable
    FlowTable table;
    std::vector<uint8_t> pkt_v6;
    append_ethernet(pkt_v6, ethertype::IPV6);
    append_ipv6(pkt_v6, 20, ipproto::TCP, addr1, addr2);
    append_tcp(pkt_v6, 50000, 443, 100, 0, 0x02 /* SYN */);

    ParsedPacket p_v6 = ProtocolParser::parse(pkt_v6.data(), pkt_v6.size());
    assert(p_v6.is_valid());
    assert(p_v6.is_ipv6());

    auto entry = table.process_packet(p_v6, 1500000, pkt_v6.size());
    assert(entry != nullptr);
    assert(table.size() == 1);
    assert(entry->key().src.ip.is_v6());
    assert(entry->stats().total_packets() == 1);
}

void test_tcp_handshake_and_lifecycle() {
    std::cout << "[TEST] TCP Handshake and Lifecycle Tracking..." << std::endl;
    FlowTable table;

    uint32_t client_ip = 0xC0A80164; // 192.168.1.100
    uint32_t server_ip = 0x0A000001; // 10.0.0.1
    uint16_t client_port = 50000;
    uint16_t server_port = 80;

    // 1. Client -> Server SYN
    std::vector<uint8_t> pkt_syn;
    append_ethernet(pkt_syn, ethertype::IPV4);
    append_ipv4(pkt_syn, 40, ipproto::TCP, client_ip, server_ip);
    append_tcp(pkt_syn, client_port, server_port, 1000, 0, 0x02 /* SYN */);

    ParsedPacket p_syn = ProtocolParser::parse(pkt_syn.data(), pkt_syn.size());
    auto entry = table.process_packet(p_syn, 1000000, pkt_syn.size());
    assert(entry != nullptr);
    assert(table.size() == 1);
    assert(entry->tcp_state_machine().state() == TcpState::SynSent);
    assert(entry->state() == FlowState::Active);
    assert(entry->stats().total_packets() == 1);

    // 2. Server -> Client SYN-ACK
    std::vector<uint8_t> pkt_syn_ack;
    append_ethernet(pkt_syn_ack, ethertype::IPV4);
    append_ipv4(pkt_syn_ack, 40, ipproto::TCP, server_ip, client_ip);
    append_tcp(pkt_syn_ack, server_port, client_port, 2000, 1001, 0x12 /* SYN-ACK */);

    ParsedPacket p_syn_ack = ProtocolParser::parse(pkt_syn_ack.data(), pkt_syn_ack.size());
    entry = table.process_packet(p_syn_ack, 1010000, pkt_syn_ack.size());
    assert(entry->tcp_state_machine().state() == TcpState::SynReceived);
    assert(entry->stats().total_packets() == 2);

    // 3. Client -> Server ACK
    std::vector<uint8_t> pkt_ack;
    append_ethernet(pkt_ack, ethertype::IPV4);
    append_ipv4(pkt_ack, 40, ipproto::TCP, client_ip, server_ip);
    append_tcp(pkt_ack, client_port, server_port, 1001, 2001, 0x10 /* ACK */);

    ParsedPacket p_ack = ProtocolParser::parse(pkt_ack.data(), pkt_ack.size());
    entry = table.process_packet(p_ack, 1020000, pkt_ack.size());
    assert(entry->tcp_state_machine().state() == TcpState::Established);
    assert(entry->state() == FlowState::Established);
    assert(entry->stats().total_packets() == 3);

    // 4. Client -> Server Data (HTTP Request, 50 bytes payload)
    std::string http_req = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    std::vector<uint8_t> pkt_data_req;
    append_ethernet(pkt_data_req, ethertype::IPV4);
    append_ipv4(pkt_data_req, static_cast<uint16_t>(40 + http_req.size()), ipproto::TCP, client_ip, server_ip);
    append_tcp(pkt_data_req, client_port, server_port, 1001, 2001, 0x18 /* PSH-ACK */);
    pkt_data_req.insert(pkt_data_req.end(), http_req.begin(), http_req.end());

    ParsedPacket p_data_req = ProtocolParser::parse(pkt_data_req.data(), pkt_data_req.size());
    entry = table.process_packet(p_data_req, 1030000, pkt_data_req.size());
    assert(entry->stats().total_packets() == 4);
    assert(entry->stats().total_payload_bytes() == http_req.size());
    assert(entry->state() == FlowState::Established);

    // 5. Server -> Client Data (HTTP Response, 100 bytes payload)
    std::string http_resp = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!";
    std::vector<uint8_t> pkt_data_resp;
    append_ethernet(pkt_data_resp, ethertype::IPV4);
    append_ipv4(pkt_data_resp, static_cast<uint16_t>(40 + http_resp.size()), ipproto::TCP, server_ip, client_ip);
    append_tcp(pkt_data_resp, server_port, client_port, 2001, 1001 + static_cast<uint32_t>(http_req.size()), 0x18 /* PSH-ACK */);
    pkt_data_resp.insert(pkt_data_resp.end(), http_resp.begin(), http_resp.end());

    ParsedPacket p_data_resp = ProtocolParser::parse(pkt_data_resp.data(), pkt_data_resp.size());
    entry = table.process_packet(p_data_resp, 1040000, pkt_data_resp.size());
    assert(entry->stats().total_packets() == 5);
    assert(entry->stats().total_payload_bytes() == http_req.size() + http_resp.size());

    // 6. Client -> Server FIN
    std::vector<uint8_t> pkt_fin1;
    append_ethernet(pkt_fin1, ethertype::IPV4);
    append_ipv4(pkt_fin1, 40, ipproto::TCP, client_ip, server_ip);
    append_tcp(pkt_fin1, client_port, server_port, 1050, 2050, 0x11 /* FIN-ACK */);

    ParsedPacket p_fin1 = ProtocolParser::parse(pkt_fin1.data(), pkt_fin1.size());
    entry = table.process_packet(p_fin1, 1050000, pkt_fin1.size());
    assert(entry->state() == FlowState::Closing);

    // 7. Server -> Client FIN
    std::vector<uint8_t> pkt_fin2;
    append_ethernet(pkt_fin2, ethertype::IPV4);
    append_ipv4(pkt_fin2, 40, ipproto::TCP, server_ip, client_ip);
    append_tcp(pkt_fin2, server_port, client_port, 2050, 1051, 0x11 /* FIN-ACK */);

    ParsedPacket p_fin2 = ProtocolParser::parse(pkt_fin2.data(), pkt_fin2.size());
    entry = table.process_packet(p_fin2, 1060000, pkt_fin2.size());
    assert(entry->tcp_state_machine().state() == TcpState::Closed);
    assert(entry->state() == FlowState::Closed);
    assert(entry->stats().total_packets() == 7);
    assert(entry->stats().duration_us() == 60000);
}

void test_tcp_rst_and_midstream() {
    std::cout << "[TEST] TCP RST and Mid-Stream Handling..." << std::endl;
    FlowTable table;

    // 1. Mid-stream pickup (packet starts with ACK + data without seeing SYN)
    std::vector<uint8_t> pkt_mid;
    append_ethernet(pkt_mid, ethertype::IPV4);
    append_ipv4(pkt_mid, 50, ipproto::TCP, 0x0A000001, 0x0A000002);
    append_tcp(pkt_mid, 1111, 2222, 500, 600, 0x10 /* ACK */);
    pkt_mid.resize(pkt_mid.size() + 10, 'A');

    ParsedPacket p_mid = ProtocolParser::parse(pkt_mid.data(), pkt_mid.size());
    auto entry = table.process_packet(p_mid, 2000000, pkt_mid.size());
    assert(entry != nullptr);
    assert(entry->tcp_state_machine().state() == TcpState::Established);
    assert(entry->state() == FlowState::Established);

    // 2. RST packet terminates connection
    std::vector<uint8_t> pkt_rst;
    append_ethernet(pkt_rst, ethertype::IPV4);
    append_ipv4(pkt_rst, 40, ipproto::TCP, 0x0A000002, 0x0A000001);
    append_tcp(pkt_rst, 2222, 1111, 600, 510, 0x04 /* RST */);

    ParsedPacket p_rst = ProtocolParser::parse(pkt_rst.data(), pkt_rst.size());
    entry = table.process_packet(p_rst, 2010000, pkt_rst.size());
    assert(entry->tcp_state_machine().state() == TcpState::Reset);
    assert(entry->state() == FlowState::Closed);
}

void test_udp_flow_tracking() {
    std::cout << "[TEST] UDP Flow Tracking..." << std::endl;
    FlowTable table;

    uint32_t client_ip = 0x0A000001;
    uint32_t dns_server = 0x08080808;

    // 1. Query (Forward)
    std::vector<uint8_t> pkt_q;
    append_ethernet(pkt_q, ethertype::IPV4);
    append_ipv4(pkt_q, 48, ipproto::UDP, client_ip, dns_server);
    append_udp(pkt_q, 53535, 53, 28);
    pkt_q.resize(pkt_q.size() + 20, 0xAA);

    ParsedPacket p_q = ProtocolParser::parse(pkt_q.data(), pkt_q.size());
    auto entry = table.process_packet(p_q, 3000000, pkt_q.size());
    assert(entry != nullptr);
    assert(table.size() == 1);
    assert(entry->state() == FlowState::Active);
    assert(entry->stats().total_packets() == 1);

    // 2. Response (Reverse)
    std::vector<uint8_t> pkt_r;
    append_ethernet(pkt_r, ethertype::IPV4);
    append_ipv4(pkt_r, 68, ipproto::UDP, dns_server, client_ip);
    append_udp(pkt_r, 53, 53535, 48);
    pkt_r.resize(pkt_r.size() + 40, 0xBB);

    ParsedPacket p_r = ProtocolParser::parse(pkt_r.data(), pkt_r.size());
    entry = table.process_packet(p_r, 3005000, pkt_r.size());
    assert(entry->state() == FlowState::Established);
    assert(entry->stats().total_packets() == 2);
    assert(entry->stats().total_payload_bytes() == 60);
    assert(entry->stats().duration_us() == 5000);
}

void test_flow_expiration_and_cleanup() {
    std::cout << "[TEST] Flow Expiration and Idle Eviction..." << std::endl;
    FlowTable table;

    FlowTimeoutConfig config;
    config.tcp_syn_timeout_us = 5 * 1000000ULL;        // 5s
    config.tcp_established_timeout_us = 60 * 1000000ULL;// 60s
    config.udp_idle_timeout_us = 10 * 1000000ULL;       // 10s
    table.set_timeout_config(config);

    uint64_t t0 = 100000000ULL;

    // 1. Insert Incomplete TCP SYN (timestamp = t0)
    std::vector<uint8_t> pkt_syn;
    append_ethernet(pkt_syn, ethertype::IPV4);
    append_ipv4(pkt_syn, 40, ipproto::TCP, 0x0A000001, 0x0A000002);
    append_tcp(pkt_syn, 1000, 80, 1, 0, 0x02);
    table.process_packet(ProtocolParser::parse(pkt_syn.data(), pkt_syn.size()), t0, pkt_syn.size());

    // 2. Insert UDP Flow (timestamp = t0)
    std::vector<uint8_t> pkt_udp;
    append_ethernet(pkt_udp, ethertype::IPV4);
    append_ipv4(pkt_udp, 28, ipproto::UDP, 0x0A000003, 0x0A000004);
    append_udp(pkt_udp, 2000, 53, 8);
    table.process_packet(ProtocolParser::parse(pkt_udp.data(), pkt_udp.size()), t0, pkt_udp.size());

    // 3. Insert Established TCP Flow (timestamp = t0)
    std::vector<uint8_t> pkt_est;
    append_ethernet(pkt_est, ethertype::IPV4);
    append_ipv4(pkt_est, 40, ipproto::TCP, 0x0A000005, 0x0A000006);
    append_tcp(pkt_est, 3000, 443, 1, 1, 0x10);
    table.process_packet(ProtocolParser::parse(pkt_est.data(), pkt_est.size()), t0, pkt_est.size());

    assert(table.size() == 3);

    // Advance to t0 + 6 seconds (SYN flow should expire, UDP & Established should remain)
    size_t evicted = table.cleanup_expired(t0 + 6000000ULL);
    assert(evicted == 1);
    assert(table.size() == 2);

    // Advance to t0 + 12 seconds (UDP flow should expire, Established TCP remains)
    evicted = table.cleanup_expired(t0 + 12000000ULL);
    assert(evicted == 1);
    assert(table.size() == 1);

    // Advance to t0 + 65 seconds (Established TCP expires)
    evicted = table.cleanup_expired(t0 + 65000000ULL);
    assert(evicted == 1);
    assert(table.size() == 0);
    assert(table.empty());
}

void test_malformed_and_unsupported_packets() {
    std::cout << "[TEST] Malformed and Unsupported Packets..." << std::endl;
    FlowTable table;

    // 1. Invalid packet (corrupt IPv4 IHL)
    std::vector<uint8_t> pkt_bad;
    append_ethernet(pkt_bad, ethertype::IPV4);
    pkt_bad.resize(pkt_bad.size() + 20, 0);
    pkt_bad[14] = 0x44; // IHL 4 is invalid

    ParsedPacket p_bad = ProtocolParser::parse(pkt_bad.data(), pkt_bad.size());
    assert(!p_bad.is_valid());
    auto entry = table.process_packet(p_bad, 1000000, pkt_bad.size());
    assert(entry == nullptr);
    assert(table.empty());

    // 2. Non-initial fragmented packet (no L4 header)
    std::vector<uint8_t> pkt_frag;
    append_ethernet(pkt_frag, ethertype::IPV4);
    append_ipv4(pkt_frag, 40, ipproto::TCP, 0x0A000001, 0x0A000002);
    pkt_frag[14 + 6] = 0x20; // MF=1, offset > 0
    pkt_frag[14 + 7] = 0x10;
    pkt_frag.resize(pkt_frag.size() + 20, 'F');

    ParsedPacket p_frag = ProtocolParser::parse(pkt_frag.data(), pkt_frag.size());
    entry = table.process_packet(p_frag, 1000000, pkt_frag.size());
    assert(entry == nullptr);
    assert(table.empty());
}

static void write_u32_le(std::ostream& os, uint32_t val) {
    os.write(reinterpret_cast<const char*>(&val), sizeof(val));
}

static void write_u16_le(std::ostream& os, uint16_t val) {
    os.write(reinterpret_cast<const char*>(&val), sizeof(val));
}

void test_integration_pcap_to_flow_table() {
    std::cout << "[TEST] Integration: PcapReader -> ProtocolParser -> FlowTable..." << std::endl;
    std::stringstream pcap_stream(std::ios::in | std::ios::out | std::ios::binary);

    // Global Header
    write_u32_le(pcap_stream, pcap_magic::MICROSEC_NATIVE);
    write_u16_le(pcap_stream, 2);
    write_u16_le(pcap_stream, 4);
    write_u32_le(pcap_stream, 0);
    write_u32_le(pcap_stream, 0);
    write_u32_le(pcap_stream, 65535);
    write_u32_le(pcap_stream, 1);

    // Packet 1: HTTP SYN (Flow A)
    std::vector<uint8_t> pkt1;
    append_ethernet(pkt1, ethertype::IPV4);
    append_ipv4(pkt1, 40, ipproto::TCP, 0x0A000001, 0x0A000002);
    append_tcp(pkt1, 50000, 80, 100, 0, 0x02);

    write_u32_le(pcap_stream, 1600000000);
    write_u32_le(pcap_stream, 1000);
    write_u32_le(pcap_stream, static_cast<uint32_t>(pkt1.size()));
    write_u32_le(pcap_stream, static_cast<uint32_t>(pkt1.size()));
    pcap_stream.write(reinterpret_cast<const char*>(pkt1.data()), pkt1.size());

    // Packet 2: DNS Query (Flow B)
    std::vector<uint8_t> pkt2;
    append_ethernet(pkt2, ethertype::IPV4);
    append_ipv4(pkt2, 38, ipproto::UDP, 0x0A000001, 0x08080808);
    append_udp(pkt2, 60000, 53, 18);
    pkt2.resize(pkt2.size() + 10, 'D');

    write_u32_le(pcap_stream, 1600000000);
    write_u32_le(pcap_stream, 2000);
    write_u32_le(pcap_stream, static_cast<uint32_t>(pkt2.size()));
    write_u32_le(pcap_stream, static_cast<uint32_t>(pkt2.size()));
    pcap_stream.write(reinterpret_cast<const char*>(pkt2.data()), pkt2.size());

    // Packet 3: HTTP SYN-ACK (Flow A return)
    std::vector<uint8_t> pkt3;
    append_ethernet(pkt3, ethertype::IPV4);
    append_ipv4(pkt3, 40, ipproto::TCP, 0x0A000002, 0x0A000001);
    append_tcp(pkt3, 80, 50000, 200, 101, 0x12);

    write_u32_le(pcap_stream, 1600000000);
    write_u32_le(pcap_stream, 3000);
    write_u32_le(pcap_stream, static_cast<uint32_t>(pkt3.size()));
    write_u32_le(pcap_stream, static_cast<uint32_t>(pkt3.size()));
    pcap_stream.write(reinterpret_cast<const char*>(pkt3.data()), pkt3.size());

    // Read with PcapReader and feed to FlowTable
    PcapReader reader;
    assert(reader.open(pcap_stream) == PcapErrorCode::Success);

    FlowTable flow_table;
    PacketRecord record;
    size_t ingested = 0;

    while (reader.read_next_packet(record) == PcapErrorCode::Success) {
        ParsedPacket parsed = ProtocolParser::parse(record);
        assert(parsed.is_valid());
        auto flow = flow_table.process_packet(record, parsed, reader.global_header().is_nanosecond_resolution);
        assert(flow != nullptr);
        ++ingested;
    }

    assert(ingested == 3);
    assert(flow_table.size() == 2); // 1 TCP flow + 1 UDP flow
}

int main() {
    std::cout << "========================================\n";
    std::cout << "  Stage 3 Flow Tracking Test Suite     \n";
    std::cout << "========================================\n";

    test_timestamp_normalization();
    test_ipv4_canonical_normalization();
    test_ipv6_canonical_normalization();
    test_tcp_handshake_and_lifecycle();
    test_tcp_rst_and_midstream();
    test_udp_flow_tracking();
    test_flow_expiration_and_cleanup();
    test_malformed_and_unsupported_packets();
    test_integration_pcap_to_flow_table();

    std::cout << "All Stage 3 Flow Tracking tests PASSED!\n";
    return 0;
}
