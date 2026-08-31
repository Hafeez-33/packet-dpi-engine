#include "dpi/dpi/dns_parser.h"
#include "dpi/dpi/dpi_engine.h"
#include "dpi/dpi/http_parser.h"
#include "dpi/dpi/tls_parser.h"
#include "dpi/flow/flow_table.h"
#include "dpi/packet/pcap_reader.h"
#include "dpi/protocols/protocol_parser.h"
#include <cassert>
#include <iostream>
#include <sstream>
#include <vector>

using namespace dpi;

// Helpers to construct byte sequences
static void push_u16_be(std::vector<uint8_t>& buf, uint16_t val) {
    buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

static void push_u24_be(std::vector<uint8_t>& buf, uint32_t val) {
    buf.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

static void push_u32_be(std::vector<uint8_t>& buf, uint32_t val) {
    buf.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

// Build a valid TLS 1.2 / 1.3 ClientHello payload with optional SNI
static std::vector<uint8_t> make_tls_client_hello(const std::string& sni) {
    std::vector<uint8_t> body;

    // Client Version (TLS 1.2 = 0x0303)
    push_u16_be(body, 0x0303);

    // Random (32 bytes)
    for (int i = 0; i < 32; ++i) body.push_back(static_cast<uint8_t>(i));

    // Session ID length = 0
    body.push_back(0);

    // Cipher Suites (1 suite = 2 bytes)
    push_u16_be(body, 2);
    push_u16_be(body, 0xC02F); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

    // Compression Methods (1 method = 1 byte: 0x00 null)
    body.push_back(1);
    body.push_back(0);

    // Extensions
    std::vector<uint8_t> extensions;
    if (!sni.empty()) {
        // SNI Extension Type 0x0000
        push_u16_be(extensions, 0x0000);

        // SNI Extension Length = 2 + 1 + 2 + sni.size()
        uint16_t sni_ext_len = static_cast<uint16_t>(5 + sni.size());
        push_u16_be(extensions, sni_ext_len);

        // Server Name List Length = 1 + 2 + sni.size()
        push_u16_be(extensions, static_cast<uint16_t>(3 + sni.size()));

        // Name Type 0x00 (host_name)
        extensions.push_back(0x00);

        // Host Name Length
        push_u16_be(extensions, static_cast<uint16_t>(sni.size()));

        // Host Name String
        extensions.insert(extensions.end(), sni.begin(), sni.end());
    }

    // Extensions Length
    push_u16_be(body, static_cast<uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());

    // Handshake Layer: Type 0x01 (ClientHello) + 3-byte Length
    std::vector<uint8_t> handshake;
    handshake.push_back(0x01);
    push_u24_be(handshake, static_cast<uint32_t>(body.size()));
    handshake.insert(handshake.end(), body.begin(), body.end());

    // Record Layer: Type 0x16 (Handshake) + Version 0x0301 + 2-byte Length
    std::vector<uint8_t> record;
    record.push_back(0x16);
    push_u16_be(record, 0x0301);
    push_u16_be(record, static_cast<uint16_t>(handshake.size()));
    record.insert(record.end(), handshake.begin(), handshake.end());

    return record;
}

// Build a valid DNS Query packet for a domain name
static std::vector<uint8_t> make_dns_query(uint16_t txid, const std::string& domain, uint16_t qtype = 1) {
    std::vector<uint8_t> dns;
    push_u16_be(dns, txid);
    push_u16_be(dns, 0x0100); // Standard Query, RD=1
    push_u16_be(dns, 1);      // QDCOUNT = 1
    push_u16_be(dns, 0);      // ANCOUNT = 0
    push_u16_be(dns, 0);      // NSCOUNT = 0
    push_u16_be(dns, 0);      // ARCOUNT = 0

    // Encode QNAME: e.g. "www.google.com" -> \x03www\x06google\x03com\x00
    std::istringstream iss(domain);
    std::string token;
    while (std::getline(iss, token, '.')) {
        if (!token.empty()) {
            dns.push_back(static_cast<uint8_t>(token.size()));
            dns.insert(dns.end(), token.begin(), token.end());
        }
    }
    dns.push_back(0x00); // End of QNAME

    push_u16_be(dns, qtype); // QTYPE (1 = A)
    push_u16_be(dns, 1);     // QCLASS (1 = IN)

    return dns;
}

// Helpers for full network packet wrapping
static void append_ethernet(std::vector<uint8_t>& buf, uint16_t ethertype) {
    for (int i = 0; i < 12; ++i) buf.push_back(0);
    push_u16_be(buf, ethertype);
}

static void append_ipv4(std::vector<uint8_t>& buf, uint16_t total_len, uint8_t proto,
                        uint32_t src_ip, uint32_t dst_ip) {
    buf.push_back(0x45);
    buf.push_back(0x00);
    push_u16_be(buf, total_len);
    push_u16_be(buf, 0x1234);
    push_u16_be(buf, 0x4000);
    buf.push_back(64);
    buf.push_back(proto);
    push_u16_be(buf, 0);
    push_u32_be(buf, src_ip);
    push_u32_be(buf, dst_ip);
}

static void append_tcp(std::vector<uint8_t>& buf, uint16_t src_port, uint16_t dst_port,
                       uint32_t seq, uint32_t ack, uint8_t flags_byte) {
    push_u16_be(buf, src_port);
    push_u16_be(buf, dst_port);
    push_u32_be(buf, seq);
    push_u32_be(buf, ack);
    push_u16_be(buf, (5u << 12) | flags_byte);
    push_u16_be(buf, 65535);
    push_u16_be(buf, 0);
    push_u16_be(buf, 0);
}

// -------------------------------------------------------------
// Test Functions
// -------------------------------------------------------------

void test_tls_client_hello() {
    std::cout << "[TEST] TLS ClientHello with and without SNI..." << std::endl;

    // 1. Valid TLS with SNI
    {
        std::vector<uint8_t> tls_raw = make_tls_client_hello("github.com");
        std::string_view payload(reinterpret_cast<const char*>(tls_raw.data()), tls_raw.size());

        TlsMetadata meta;
        assert(TlsParser::parse_client_hello(payload, meta));
        assert(meta.legacy_version == 0x0301);
        assert(meta.client_version == 0x0303);
        assert(meta.has_sni);
        assert(meta.sni == "github.com");

        DpiResult res = DpiEngine::inspect(payload, static_cast<uint8_t>(FlowProtocol::TCP), 50000, 443);
        assert(res.matched);
        assert(res.metadata.protocol == AppProtocol::TLS);
        assert(res.metadata.hostname == "github.com");
    }

    // 2. Valid TLS without SNI
    {
        std::vector<uint8_t> tls_raw = make_tls_client_hello("");
        std::string_view payload(reinterpret_cast<const char*>(tls_raw.data()), tls_raw.size());

        TlsMetadata meta;
        assert(TlsParser::parse_client_hello(payload, meta));
        assert(!meta.has_sni);
        assert(meta.sni.empty());

        DpiResult res = DpiEngine::inspect(payload, static_cast<uint8_t>(FlowProtocol::TCP), 50000, 443);
        assert(res.matched);
        assert(res.metadata.protocol == AppProtocol::TLS);
        assert(res.metadata.hostname.empty());
    }

    // 3. Truncated record header (< 5 bytes)
    {
        std::vector<uint8_t> short_rec = {0x16, 0x03, 0x01};
        std::string_view payload(reinterpret_cast<const char*>(short_rec.data()), short_rec.size());
        TlsMetadata meta;
        assert(!TlsParser::parse_client_hello(payload, meta));
    }

    // 4. Corrupted extension length
    {
        std::vector<uint8_t> tls_raw = make_tls_client_hello("example.com");
        // Corrupt extension length
        tls_raw[tls_raw.size() - 10] = 0xFF;
        tls_raw[tls_raw.size() - 9] = 0xFF;

        std::string_view payload(reinterpret_cast<const char*>(tls_raw.data()), tls_raw.size());
        TlsMetadata meta;
        // Still returns true as ClientHello, but SNI parsing gracefully terminates
        assert(TlsParser::parse_client_hello(payload, meta));
    }
}

void test_http_request() {
    std::cout << "[TEST] HTTP/1.x Request Line and Host Parsing..." << std::endl;

    // 1. Standard GET with Host
    {
        std::string req = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.68.0\r\n\r\n";
        HttpMetadata meta;
        assert(HttpParser::parse_request(req, meta));
        assert(meta.method == "GET");
        assert(meta.uri == "/index.html");
        assert(meta.version == "HTTP/1.1");
        assert(meta.has_host);
        assert(meta.host == "example.com");

        DpiResult res = DpiEngine::inspect(req, static_cast<uint8_t>(FlowProtocol::TCP), 50000, 80);
        assert(res.matched);
        assert(res.metadata.protocol == AppProtocol::HTTP);
        assert(res.metadata.hostname == "example.com");
    }

    // 2. POST with Port in Host header
    {
        std::string req = "POST /api/v1/data HTTP/1.1\r\nHost: api.service.local:8080\r\nContent-Length: 0\r\n\r\n";
        HttpMetadata meta;
        assert(HttpParser::parse_request(req, meta));
        assert(meta.method == "POST");
        assert(meta.has_host);
        assert(meta.host == "api.service.local"); // Port stripped
    }

    // 3. Case-insensitive Host header
    {
        std::string req = "HEAD / HTTP/1.0\r\nhost:   sub.domain.org   \r\n\r\n";
        HttpMetadata meta;
        assert(HttpParser::parse_request(req, meta));
        assert(meta.method == "HEAD");
        assert(meta.version == "HTTP/1.0");
        assert(meta.has_host);
        assert(meta.host == "sub.domain.org");
    }

    // 4. HTTP/1.0 without Host header
    {
        std::string req = "GET / HTTP/1.0\r\nAccept: */*\r\n\r\n";
        HttpMetadata meta;
        assert(HttpParser::parse_request(req, meta));
        assert(meta.method == "GET");
        assert(!meta.has_host);
        assert(meta.host.empty());
    }

    // 5. Malformed request line
    {
        std::string req = "GETINVALIDLINE\r\n\r\n";
        HttpMetadata meta;
        assert(!HttpParser::parse_request(req, meta));
    }
}

void test_dns_query() {
    std::cout << "[TEST] DNS Query, QNAME, and Cycle-Safe Compression..." << std::endl;

    // 1. Standard DNS Query (www.google.com)
    {
        std::vector<uint8_t> dns_raw = make_dns_query(0x1234, "www.google.com", 1);
        std::string_view payload(reinterpret_cast<const char*>(dns_raw.data()), dns_raw.size());

        DnsMetadata meta;
        assert(DnsParser::parse_query(payload, meta));
        assert(meta.transaction_id == 0x1234);
        assert(meta.qname == "www.google.com");
        assert(meta.qtype == 1);
        assert(meta.qclass == 1);

        DpiResult res = DpiEngine::inspect(payload, static_cast<uint8_t>(FlowProtocol::UDP), 53535, 53);
        assert(res.matched);
        assert(res.metadata.protocol == AppProtocol::DNS);
        assert(res.metadata.hostname == "www.google.com");
    }

    // 2. DNS Compression Pointer (Valid)
    {
        std::vector<uint8_t> dns_raw = make_dns_query(0xABCD, "sub.example.com", 28 /* AAAA */);
        // Add a second pointer-based query pointing to "example.com" at offset 16
        // Header (12) + \x03sub (4) = offset 16 has \x07example\x03com\x00
        std::vector<uint8_t> comp_query;
        push_u16_be(comp_query, 0x5678);
        push_u16_be(comp_query, 0x0100);
        push_u16_be(comp_query, 1);
        push_u16_be(comp_query, 0);
        push_u16_be(comp_query, 0);
        push_u16_be(comp_query, 0);

        // First label: \x03new at offset 12..15
        comp_query.push_back(0x03);
        comp_query.push_back('n'); comp_query.push_back('e'); comp_query.push_back('w');
        // Pointer to offset 18 (where target label starts)
        comp_query.push_back(0xC0);
        comp_query.push_back(18);

        // Append base target label "\x03org\x00" at offset 18..22
        comp_query.push_back(0x03);
        comp_query.push_back('o'); comp_query.push_back('r'); comp_query.push_back('g');
        comp_query.push_back(0x00);
        push_u16_be(comp_query, 1);
        push_u16_be(comp_query, 1);

        std::string_view payload(reinterpret_cast<const char*>(comp_query.data()), comp_query.size());
        DnsMetadata meta;
        assert(DnsParser::parse_query(payload, meta));
        assert(meta.qname == "new.org");
    }

    // 3. DNS Compression Pointer Cycle Prevention (Self-Loop: 0xC00C at offset 12)
    {
        std::vector<uint8_t> cycle_dns;
        push_u16_be(cycle_dns, 0x9999);
        push_u16_be(cycle_dns, 0x0100);
        push_u16_be(cycle_dns, 1);
        push_u16_be(cycle_dns, 0);
        push_u16_be(cycle_dns, 0);
        push_u16_be(cycle_dns, 0);

        // Self-referencing pointer to offset 12 (itself)
        cycle_dns.push_back(0xC0);
        cycle_dns.push_back(0x0C);

        std::string_view payload(reinterpret_cast<const char*>(cycle_dns.data()), cycle_dns.size());
        DnsMetadata meta;
        assert(!DnsParser::parse_query(payload, meta)); // Safely rejected without infinite loop
    }

    // 4. Out-of-bounds pointer
    {
        std::vector<uint8_t> oob_dns;
        push_u16_be(oob_dns, 0x1111);
        push_u16_be(oob_dns, 0x0100);
        push_u16_be(oob_dns, 1);
        push_u16_be(oob_dns, 0);
        push_u16_be(oob_dns, 0);
        push_u16_be(oob_dns, 0);
        oob_dns.push_back(0xC0);
        oob_dns.push_back(0xFF); // Points to offset 255 (beyond 14 bytes)

        std::string_view payload(reinterpret_cast<const char*>(oob_dns.data()), oob_dns.size());
        DnsMetadata meta;
        assert(!DnsParser::parse_query(payload, meta));
    }
}

void test_tcp_fragmentation_and_buffer_lifecycle() {
    std::cout << "[TEST] TCP Fragmentation and Bounded DPI Reassembly..." << std::endl;
    FlowTable table;

    uint32_t client_ip = 0x0A000001;
    uint32_t server_ip = 0x0A000002;
    uint16_t client_port = 45000;
    uint16_t server_port = 80;

    // 1. HTTP request split across 2 packets
    // Packet 1: "GET /api/status HTTP/1.1\r\n"
    std::string chunk1 = "GET /api/status HTTP/1.1\r\n";
    std::vector<uint8_t> pkt1;
    append_ethernet(pkt1, ethertype::IPV4);
    append_ipv4(pkt1, static_cast<uint16_t>(40 + chunk1.size()), ipproto::TCP, client_ip, server_ip);
    append_tcp(pkt1, client_port, server_port, 1000, 2000, 0x18);
    pkt1.insert(pkt1.end(), chunk1.begin(), chunk1.end());

    ParsedPacket p1 = ProtocolParser::parse(pkt1.data(), pkt1.size());
    auto entry = table.process_packet(p1, 1000000, pkt1.size());
    assert(entry != nullptr);
    // Incomplete request line + headers -> not yet classified, payload buffered in reassembly buffer
    assert(!entry->is_classified());
    assert(entry->dpi_buffer_size() == chunk1.size());

    // Packet 2: "Host: fragmented.service.com\r\n\r\n"
    std::string chunk2 = "Host: fragmented.service.com\r\n\r\n";
    std::vector<uint8_t> pkt2;
    append_ethernet(pkt2, ethertype::IPV4);
    append_ipv4(pkt2, static_cast<uint16_t>(40 + chunk2.size()), ipproto::TCP, client_ip, server_ip);
    append_tcp(pkt2, client_port, server_port, 1000 + static_cast<uint32_t>(chunk1.size()), 2000, 0x18);
    pkt2.insert(pkt2.end(), chunk2.begin(), chunk2.end());

    ParsedPacket p2 = ProtocolParser::parse(pkt2.data(), pkt2.size());
    entry = table.process_packet(p2, 1010000, pkt2.size());
    assert(entry->is_classified());
    assert(entry->l7_metadata().protocol == AppProtocol::HTTP);
    assert(entry->l7_metadata().hostname == "fragmented.service.com");

    // Verify buffer was immediately released upon classification!
    assert(entry->dpi_buffer_size() == 0);
    assert(entry->is_dpi_complete());

    // 2. Subsequent data packets continue updating statistics and bypass DPI
    std::string chunk3 = "ExtraDataPayloadBytes";
    std::vector<uint8_t> pkt3;
    append_ethernet(pkt3, ethertype::IPV4);
    append_ipv4(pkt3, static_cast<uint16_t>(40 + chunk3.size()), ipproto::TCP, client_ip, server_ip);
    append_tcp(pkt3, client_port, server_port, 2000, 2000, 0x18);
    pkt3.insert(pkt3.end(), chunk3.begin(), chunk3.end());

    ParsedPacket p3 = ProtocolParser::parse(pkt3.data(), pkt3.size());
    entry = table.process_packet(p3, 1020000, pkt3.size());
    assert(entry->stats().total_packets() == 3);
    assert(entry->is_classified());
    assert(entry->dpi_buffer_size() == 0); // Still 0
}

void test_tls_split_across_packets() {
    std::cout << "[TEST] TLS ClientHello Split Across Packets..." << std::endl;
    FlowTable table;

    uint32_t client_ip = 0x0A000003;
    uint32_t server_ip = 0x0A000004;
    uint16_t client_port = 52000;
    uint16_t server_port = 443;

    std::vector<uint8_t> full_tls = make_tls_client_hello("cloud.google.com");
    size_t split_point = 25; // Split midway through ClientHello

    std::vector<uint8_t> chunk1(full_tls.begin(), full_tls.begin() + split_point);
    std::vector<uint8_t> chunk2(full_tls.begin() + split_point, full_tls.end());

    // Packet 1: First half of TLS ClientHello
    std::vector<uint8_t> pkt1;
    append_ethernet(pkt1, ethertype::IPV4);
    append_ipv4(pkt1, static_cast<uint16_t>(40 + chunk1.size()), ipproto::TCP, client_ip, server_ip);
    append_tcp(pkt1, client_port, server_port, 100, 100, 0x18);
    pkt1.insert(pkt1.end(), chunk1.begin(), chunk1.end());

    ParsedPacket p1 = ProtocolParser::parse(pkt1.data(), pkt1.size());
    auto entry = table.process_packet(p1, 2000000, pkt1.size());
    assert(entry != nullptr);
    assert(!entry->is_classified());
    assert(entry->dpi_buffer_size() == split_point);

    // Packet 2: Remainder of TLS ClientHello with SNI
    std::vector<uint8_t> pkt2;
    append_ethernet(pkt2, ethertype::IPV4);
    append_ipv4(pkt2, static_cast<uint16_t>(40 + chunk2.size()), ipproto::TCP, client_ip, server_ip);
    append_tcp(pkt2, client_port, server_port, 100 + static_cast<uint32_t>(split_point), 100, 0x18);
    pkt2.insert(pkt2.end(), chunk2.begin(), chunk2.end());

    ParsedPacket p2 = ProtocolParser::parse(pkt2.data(), pkt2.size());
    entry = table.process_packet(p2, 2010000, pkt2.size());
    assert(entry->is_classified());
    assert(entry->l7_metadata().protocol == AppProtocol::TLS);
    assert(entry->l7_metadata().hostname == "cloud.google.com");
    assert(entry->dpi_buffer_size() == 0); // Released!
}

void test_dpi_buffer_limit_abandon() {
    std::cout << "[TEST] Bounded DPI Reassembly Limit Exhaustion..." << std::endl;
    FlowTable table;

    uint32_t client_ip = 0x0A000005;
    uint32_t server_ip = 0x0A000006;
    uint16_t client_port = 60000;
    uint16_t server_port = 9999;

    // Send 9 KB of unknown binary garbage in chunks to exceed 8 KB limit
    std::string garbage(1024, 'X');
    for (int i = 0; i < 9; ++i) {
        std::vector<uint8_t> pkt;
        append_ethernet(pkt, ethertype::IPV4);
        append_ipv4(pkt, static_cast<uint16_t>(40 + garbage.size()), ipproto::TCP, client_ip, server_ip);
        append_tcp(pkt, client_port, server_port, 1000 * i, 0, 0x18);
        pkt.insert(pkt.end(), garbage.begin(), garbage.end());

        ParsedPacket p = ProtocolParser::parse(pkt.data(), pkt.size());
        auto entry = table.process_packet(p, 3000000 + i * 1000, pkt.size());
        assert(entry != nullptr);
    }

    auto [key, dir] = FlowKey::create(IPAddress(IPv4Address(client_ip)), client_port,
                                      IPAddress(IPv4Address(server_ip)), server_port, 6);
    auto entry = table.find_flow(key);
    assert(entry != nullptr);
    assert(entry->is_dpi_complete());
    assert(!entry->is_classified());
    assert(entry->l7_metadata().protocol == AppProtocol::Unknown);
    assert(entry->dpi_buffer_size() == 0); // Buffer released
    assert(entry->stats().total_packets() == 9);
}

void test_synthetic_pcap_dpi_pipeline() {
    std::cout << "[TEST] End-to-End PCAP Ingestion with DPI..." << std::endl;
    std::stringstream pcap_stream(std::ios::in | std::ios::out | std::ios::binary);

    auto write_u32_le = [](std::ostream& os, uint32_t val) {
        os.write(reinterpret_cast<const char*>(&val), sizeof(val));
    };
    auto write_u16_le = [](std::ostream& os, uint16_t val) {
        os.write(reinterpret_cast<const char*>(&val), sizeof(val));
    };

    // Global Header
    write_u32_le(pcap_stream, pcap_magic::MICROSEC_NATIVE);
    write_u16_le(pcap_stream, 2);
    write_u16_le(pcap_stream, 4);
    write_u32_le(pcap_stream, 0);
    write_u32_le(pcap_stream, 0);
    write_u32_le(pcap_stream, 65535);
    write_u32_le(pcap_stream, 1);

    // 1. Packet 1: HTTP Request for wikipedia.org
    std::string http_data = "GET /wiki/Main_Page HTTP/1.1\r\nHost: wikipedia.org\r\n\r\n";
    std::vector<uint8_t> pkt1;
    append_ethernet(pkt1, ethertype::IPV4);
    append_ipv4(pkt1, static_cast<uint16_t>(40 + http_data.size()), ipproto::TCP, 0x0A000001, 0x0A000002);
    append_tcp(pkt1, 40001, 80, 100, 200, 0x18);
    pkt1.insert(pkt1.end(), http_data.begin(), http_data.end());

    write_u32_le(pcap_stream, 1600000000);
    write_u32_le(pcap_stream, 1000);
    write_u32_le(pcap_stream, static_cast<uint32_t>(pkt1.size()));
    write_u32_le(pcap_stream, static_cast<uint32_t>(pkt1.size()));
    pcap_stream.write(reinterpret_cast<const char*>(pkt1.data()), pkt1.size());

    // 2. Packet 2: TLS ClientHello for discord.com
    std::vector<uint8_t> tls_data = make_tls_client_hello("discord.com");
    std::vector<uint8_t> pkt2;
    append_ethernet(pkt2, ethertype::IPV4);
    append_ipv4(pkt2, static_cast<uint16_t>(40 + tls_data.size()), ipproto::TCP, 0x0A000001, 0x0A000003);
    append_tcp(pkt2, 40002, 443, 300, 400, 0x18);
    pkt2.insert(pkt2.end(), tls_data.begin(), tls_data.end());

    write_u32_le(pcap_stream, 1600000000);
    write_u32_le(pcap_stream, 2000);
    write_u32_le(pcap_stream, static_cast<uint32_t>(pkt2.size()));
    write_u32_le(pcap_stream, static_cast<uint32_t>(pkt2.size()));
    pcap_stream.write(reinterpret_cast<const char*>(pkt2.data()), pkt2.size());

    // 3. Packet 3: DNS Query for openai.com
    std::vector<uint8_t> dns_data = make_dns_query(0x7777, "openai.com", 1);
    std::vector<uint8_t> pkt3;
    append_ethernet(pkt3, ethertype::IPV4);
    append_ipv4(pkt3, static_cast<uint16_t>(28 + dns_data.size()), ipproto::UDP, 0x0A000001, 0x08080808);
    push_u16_be(pkt3, 53535);
    push_u16_be(pkt3, 53);
    push_u16_be(pkt3, static_cast<uint16_t>(8 + dns_data.size()));
    push_u16_be(pkt3, 0);
    pkt3.insert(pkt3.end(), dns_data.begin(), dns_data.end());

    write_u32_le(pcap_stream, 1600000000);
    write_u32_le(pcap_stream, 3000);
    write_u32_le(pcap_stream, static_cast<uint32_t>(pkt3.size()));
    write_u32_le(pcap_stream, static_cast<uint32_t>(pkt3.size()));
    pcap_stream.write(reinterpret_cast<const char*>(pkt3.data()), pkt3.size());

    // Ingest stream
    PcapReader reader;
    assert(reader.open(pcap_stream) == PcapErrorCode::Success);

    FlowTable flow_table;
    PacketRecord rec;

    while (reader.read_next_packet(rec) == PcapErrorCode::Success) {
        ParsedPacket parsed = ProtocolParser::parse(rec);
        assert(parsed.is_valid());
        auto flow = flow_table.process_packet(rec, parsed, reader.global_header().is_nanosecond_resolution);
        assert(flow != nullptr);
        assert(flow->is_classified());
    }

    assert(flow_table.size() == 3);

    // Verify classified domains
    size_t http_count = 0, tls_count = 0, dns_count = 0;
    flow_table.for_each_flow([&](const std::shared_ptr<FlowEntry>& flow) {
        if (flow->l7_metadata().protocol == AppProtocol::HTTP) {
            assert(flow->l7_metadata().hostname == "wikipedia.org");
            ++http_count;
        } else if (flow->l7_metadata().protocol == AppProtocol::TLS) {
            assert(flow->l7_metadata().hostname == "discord.com");
            ++tls_count;
        } else if (flow->l7_metadata().protocol == AppProtocol::DNS) {
            assert(flow->l7_metadata().hostname == "openai.com");
            ++dns_count;
        }
    });

    assert(http_count == 1);
    assert(tls_count == 1);
    assert(dns_count == 1);
    (void)http_count;
    (void)tls_count;
    (void)dns_count;
}

int main() {
    std::cout << "========================================\n";
    std::cout << "     Stage 4 Layer-7 DPI Test Suite     \n";
    std::cout << "========================================\n";

    test_tls_client_hello();
    test_http_request();
    test_dns_query();
    test_tcp_fragmentation_and_buffer_lifecycle();
    test_tls_split_across_packets();
    test_dpi_buffer_limit_abandon();
    test_synthetic_pcap_dpi_pipeline();

    std::cout << "All Stage 4 Layer-7 DPI tests PASSED!\n";
    return 0;
}
