#include "dpi/dpi/dpi_engine.h"
#include "dpi/flow/flow_table.h"
#include "dpi/packet/pcap_reader.h"
#include "dpi/protocols/protocol_parser.h"
#include "dpi/rules/domain_matcher.h"
#include "dpi/rules/ip_matcher.h"
#include "dpi/rules/port_matcher.h"
#include "dpi/rules/rule_engine.h"
#include "dpi/rules/rule_parser.h"
#include <cassert>
#include <iostream>
#include <sstream>
#include <vector>

using namespace dpi;

// Helpers to push byte values
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

static std::vector<uint8_t> make_tls_client_hello(const std::string& sni) {
    std::vector<uint8_t> body;
    push_u16_be(body, 0x0303);
    for (int i = 0; i < 32; ++i) body.push_back(static_cast<uint8_t>(i));
    body.push_back(0); // session id len
    push_u16_be(body, 2);
    push_u16_be(body, 0xC02F);
    body.push_back(1);
    body.push_back(0);

    std::vector<uint8_t> extensions;
    if (!sni.empty()) {
        push_u16_be(extensions, 0x0000);
        uint16_t sni_ext_len = static_cast<uint16_t>(5 + sni.size());
        push_u16_be(extensions, sni_ext_len);
        push_u16_be(extensions, static_cast<uint16_t>(3 + sni.size()));
        extensions.push_back(0x00);
        push_u16_be(extensions, static_cast<uint16_t>(sni.size()));
        extensions.insert(extensions.end(), sni.begin(), sni.end());
    }

    push_u16_be(body, static_cast<uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<uint8_t> handshake;
    handshake.push_back(0x01);
    push_u24_be(handshake, static_cast<uint32_t>(body.size()));
    handshake.insert(handshake.end(), body.begin(), body.end());

    std::vector<uint8_t> record;
    record.push_back(0x16);
    push_u16_be(record, 0x0301);
    push_u16_be(record, static_cast<uint16_t>(handshake.size()));
    record.insert(record.end(), handshake.begin(), handshake.end());

    return record;
}

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
// Unit Tests
// -------------------------------------------------------------

void test_ip_matching() {
    std::cout << "[TEST] IP & CIDR Subnet Matching (IPv4 and IPv6)..." << std::endl;

    // 1. IPv4 Exact
    IpMatcher m1 = IpMatcher::parse("192.168.1.50");
    assert(m1.is_valid());
    assert(m1.is_ipv4());
    assert(m1.matches(IPAddress(*IPv4Address::from_string("192.168.1.50"))));
    assert(!m1.matches(IPAddress(*IPv4Address::from_string("192.168.1.51"))));

    // 2. IPv4 CIDR /24
    IpMatcher m2 = IpMatcher::parse("192.168.1.0/24");
    assert(m2.is_valid());
    assert(m2.matches(IPAddress(*IPv4Address::from_string("192.168.1.1"))));
    assert(m2.matches(IPAddress(*IPv4Address::from_string("192.168.1.254"))));
    assert(!m2.matches(IPAddress(*IPv4Address::from_string("192.168.2.1"))));

    // 3. IPv4 CIDR /8
    IpMatcher m3 = IpMatcher::parse("10.0.0.0/8");
    assert(m3.is_valid());
    assert(m3.matches(IPAddress(*IPv4Address::from_string("10.250.1.99"))));
    assert(!m3.matches(IPAddress(*IPv4Address::from_string("11.0.0.1"))));

    // 4. IPv6 Exact & Subnet
    IpMatcher m4 = IpMatcher::parse("2001:db8::/32");
    assert(m4.is_valid());
    assert(m4.is_ipv6());
    assert(m4.matches(IPAddress(*IPv6Address::from_string("2001:db8:85a3::8a2e:370:7334"))));
    assert(!m4.matches(IPAddress(*IPv6Address::from_string("2001:db9::1"))));

    // 5. Wildcard Any
    IpMatcher m5 = IpMatcher::parse("any");
    assert(m5.is_any());
    assert(m5.matches(IPAddress(*IPv4Address::from_string("1.2.3.4"))));
    assert(m5.matches(IPAddress(*IPv6Address::from_string("::1"))));

    // 6. Invalid CIDR format
    IpMatcher m6 = IpMatcher::parse("999.999.999.999/24");
    assert(!m6.is_valid());
    IpMatcher m7 = IpMatcher::parse("192.168.1.0/33");
    assert(!m7.is_valid());
}

void test_port_matching() {
    std::cout << "[TEST] Port Range and List Matching..." << std::endl;

    // 1. Single Port
    PortMatcher m1 = PortMatcher::parse("80");
    assert(m1.is_valid());
    assert(m1.matches(80));
    assert(!m1.matches(81));

    // 2. Port Range
    PortMatcher m2 = PortMatcher::parse("8000-8080");
    assert(m2.is_valid());
    assert(m2.matches(8000));
    assert(m2.matches(8040));
    assert(m2.matches(8080));
    assert(!m2.matches(7999));
    assert(!m2.matches(8081));

    // 3. Port List & Mixed Ranges
    PortMatcher m3 = PortMatcher::parse("80, 443, 8000-8080");
    assert(m3.is_valid());
    assert(m3.matches(80));
    assert(m3.matches(443));
    assert(m3.matches(8050));
    assert(!m3.matches(8081));
    assert(!m3.matches(22));

    // 4. Any
    PortMatcher m4 = PortMatcher::parse("any");
    assert(m4.is_any());
    assert(m4.matches(12345));

    // 5. Invalid
    PortMatcher m5 = PortMatcher::parse("99999");
    assert(!m5.is_valid());
    PortMatcher m6 = PortMatcher::parse("9000-8000");
    assert(!m6.is_valid());
}

void test_domain_matching() {
    std::cout << "[TEST] Domain Exact and Wildcard Matching..." << std::endl;

    // 1. Exact domain
    DomainMatcher m1 = DomainMatcher::parse("doubleclick.net");
    assert(m1.is_valid());
    assert(m1.matches("doubleclick.net"));
    assert(m1.matches("DOUBLECLICK.NET")); // Case-insensitive
    assert(!m1.matches("sub.doubleclick.net"));
    assert(!m1.matches("doubleclick.org"));

    // 2. Suffix wildcard (*.tiktok.com)
    DomainMatcher m2 = DomainMatcher::parse("*.tiktok.com");
    assert(m2.is_valid());
    assert(m2.matches("tiktok.com")); // Base domain
    assert(m2.matches("api.tiktok.com"));
    assert(m2.matches("v16.api.tiktok.com"));
    assert(m2.matches("API.TIKTOK.COM"));
    assert(!m2.matches("not-tiktok.com"));
    assert(!m2.matches("tiktok.org"));

    // 3. General glob (ads.*.com)
    DomainMatcher m3 = DomainMatcher::parse("ads.*.com");
    assert(m3.is_valid());
    assert(m3.matches("ads.google.com"));
    assert(m3.matches("ads.yahoo.com"));
    assert(!m3.matches("ads.google.org"));
}

void test_json_rule_parsing() {
    std::cout << "[TEST] JSON Configuration Loading and Validation..." << std::endl;

    // 1. Valid Structured Rule Array JSON
    std::string json1 = R"({
        "version": "1.0",
        "default_action": "ALLOW",
        "rules": [
            {
                "id": 1,
                "name": "Block Telnet",
                "priority": 10,
                "action": "BLOCK",
                "dst_port": "23",
                "protocol": "TCP"
            },
            {
                "id": 2,
                "name": "Block TikTok SNI",
                "priority": 20,
                "action": "BLOCK",
                "domain": "*.tiktok.com",
                "app_protocol": "TLS"
            }
        ]
    })";

    RuleLoadResult res1 = RuleParser::parse_string(json1);
    assert(res1.success);
    assert(res1.default_action == RuleAction::Allow);
    assert(res1.rules.size() == 2);
    assert(res1.rules[0].id == 1);
    assert(res1.rules[0].action == RuleAction::Block);
    assert(res1.rules[1].domain_pattern == "*.tiktok.com");
    assert(res1.rules[1].has_l7_criteria());

    // 2. Valid Categorical Section JSON
    std::string json2 = R"({
        "version": "1.0",
        "default_action": "ALLOW",
        "rules": {
            "blocked_ips": [ "192.168.1.50", "10.0.0.0/8" ],
            "blocked_domains": [ "*.facebook.com", "doubleclick.net" ],
            "blocked_apps": [ "TLS", "HTTP", "DNS" ],
            "blocked_ports": [ 23, 445, 3389 ]
        }
    })";

    RuleLoadResult res2 = RuleParser::parse_string(json2);
    assert(res2.success);
    assert(res2.rules.size() == 10);

    // 3. Rejection of Unsupported Application Protocols in blocked_apps (Architectural Constraint 1)
    std::string json_unsupported = R"({
        "rules": {
            "blocked_apps": [ "BitTorrent" ]
        }
    })";
    RuleLoadResult res_unsupported = RuleParser::parse_string(json_unsupported);
    assert(!res_unsupported.success); // Must fail safely on unsupported apps

    // 4. Malformed JSON Error Handling
    std::string json_bad = R"({ "rules": [ { "id": 1, "name": "Broken" )";
    RuleLoadResult res_bad = RuleParser::parse_string(json_bad);
    assert(!res_bad.success);
    assert(!res_bad.error_message.empty());
}

void test_priority_and_deterministic_resolution() {
    std::cout << "[TEST] Rule Priority and Precedence Resolution..." << std::endl;
    RuleEngine engine;

    // Rule 1: Priority 50 BLOCK port 443
    Rule r1;
    r1.id = 1;
    r1.name = "Block HTTPS";
    r1.priority = 50;
    r1.action = RuleAction::Block;
    r1.dst_port_range = "443";
    r1.transport_protocol = "TCP";

    // Rule 2: Priority 10 ALLOW specific internal server on port 443
    Rule r2;
    r2.id = 2;
    r2.name = "Allow Internal Server HTTPS";
    r2.priority = 10;
    r2.action = RuleAction::Allow;
    r2.dst_ip_cidr = "10.0.0.50";
    r2.dst_port_range = "443";
    r2.transport_protocol = "TCP";

    engine.add_rule(r1);
    engine.add_rule(r2);

    auto [key1, dir1] = FlowKey::create(IPAddress(*IPv4Address::from_string("192.168.1.100")), 50000,
                                        IPAddress(*IPv4Address::from_string("10.0.0.50")), 443, 6);
    PolicyVerdict v1 = engine.evaluate_l3_l4(key1);
    assert(v1.action == RuleAction::Allow); // High-priority rule 2 wins
    assert(v1.matched_rule_id == 2);

    auto [key2, dir2] = FlowKey::create(IPAddress(*IPv4Address::from_string("192.168.1.100")), 50000,
                                        IPAddress(*IPv4Address::from_string("93.184.216.34")), 443, 6);
    PolicyVerdict v2 = engine.evaluate_l3_l4(key2);
    assert(v2.action == RuleAction::Block); // Rule 1 matches
    assert(v2.matched_rule_id == 1);
}

void test_l3_l4_vs_l7_lifecycle() {
    std::cout << "[TEST] L3/L4 vs L7 Policy Lifecycle (Architectural Constraint 2)..." << std::endl;
    auto engine = std::make_shared<RuleEngine>();

    // Configure a domain block rule for *.tiktok.com
    Rule r_domain;
    r_domain.id = 101;
    r_domain.name = "Block TikTok";
    r_domain.priority = 20;
    r_domain.action = RuleAction::Block;
    r_domain.domain_pattern = "*.tiktok.com";
    r_domain.app_protocol = "TLS";
    engine->add_rule(r_domain);

    FlowTable table;
    table.set_rule_engine(engine);

    uint32_t client_ip = 0x0A000001;
    uint32_t server_ip = 0x0A000002;
    uint16_t client_port = 45000;
    uint16_t server_port = 443;

    // Packet 1: TCP SYN (no payload, pure L3/L4)
    std::vector<uint8_t> syn_pkt;
    append_ethernet(syn_pkt, ethertype::IPV4);
    append_ipv4(syn_pkt, 40, ipproto::TCP, client_ip, server_ip);
    append_tcp(syn_pkt, client_port, server_port, 1000, 0, 0x02);

    ParsedPacket p_syn = ProtocolParser::parse(syn_pkt.data(), syn_pkt.size());
    auto entry = table.process_packet(p_syn, 1000000, syn_pkt.size());
    assert(entry != nullptr);

    // Initial L3/L4 state: no L3/L4 rules matched -> provisional default ALLOW
    assert(!entry->is_blocked());
    assert(!entry->has_final_verdict());
    assert(entry->policy_verdict().action == RuleAction::Allow);

    // Packet 2: TLS ClientHello for "v16.api.tiktok.com"
    std::vector<uint8_t> tls_raw = make_tls_client_hello("v16.api.tiktok.com");
    std::vector<uint8_t> data_pkt;
    append_ethernet(data_pkt, ethertype::IPV4);
    append_ipv4(data_pkt, static_cast<uint16_t>(40 + tls_raw.size()), ipproto::TCP, client_ip, server_ip);
    append_tcp(data_pkt, client_port, server_port, 1001, 1, 0x18);
    data_pkt.insert(data_pkt.end(), tls_raw.begin(), tls_raw.end());

    ParsedPacket p_data = ProtocolParser::parse(data_pkt.data(), data_pkt.size());
    entry = table.process_packet(p_data, 1010000, data_pkt.size());

    // Final L7 State: TLS SNI decoded -> L7 Policy evaluation matches rule 101 -> final BLOCK!
    assert(entry->is_classified());
    assert(entry->has_final_verdict());
    assert(entry->is_blocked());
    assert(entry->policy_verdict().action == RuleAction::Block);
    assert(entry->policy_verdict().matched_rule_id == 101);
}

void test_end_to_end_pcap_policy_pipeline() {
    std::cout << "[TEST] End-to-End PCAP Ingestion with Rule & Policy Engine..." << std::endl;
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

    // Stream 1: Telnet packet on port 23 -> Should be BLOCKED by L3/L4 rule
    std::string telnet_data = "Login: admin\r\n";
    std::vector<uint8_t> pkt1;
    append_ethernet(pkt1, ethertype::IPV4);
    append_ipv4(pkt1, static_cast<uint16_t>(40 + telnet_data.size()), ipproto::TCP, 0x0A000001, 0x0A000002);
    append_tcp(pkt1, 40001, 23, 100, 200, 0x18);
    pkt1.insert(pkt1.end(), telnet_data.begin(), telnet_data.end());

    write_u32_le(pcap_stream, 1600000000);
    write_u32_le(pcap_stream, 1000);
    write_u32_le(pcap_stream, static_cast<uint32_t>(pkt1.size()));
    write_u32_le(pcap_stream, static_cast<uint32_t>(pkt1.size()));
    pcap_stream.write(reinterpret_cast<const char*>(pkt1.data()), pkt1.size());

    // Stream 2: TLS ClientHello for "doubleclick.net" -> Should be BLOCKED by L7 domain rule
    std::vector<uint8_t> tls_data = make_tls_client_hello("doubleclick.net");
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

    // Stream 3: Allowed HTTPS for "github.com" -> Should be ALLOWED
    std::vector<uint8_t> tls_data3 = make_tls_client_hello("github.com");
    std::vector<uint8_t> pkt3;
    append_ethernet(pkt3, ethertype::IPV4);
    append_ipv4(pkt3, static_cast<uint16_t>(40 + tls_data3.size()), ipproto::TCP, 0x0A000001, 0x0A000004);
    append_tcp(pkt3, 40003, 443, 500, 600, 0x18);
    pkt3.insert(pkt3.end(), tls_data3.begin(), tls_data3.end());

    write_u32_le(pcap_stream, 1600000000);
    write_u32_le(pcap_stream, 3000);
    write_u32_le(pcap_stream, static_cast<uint32_t>(pkt3.size()));
    write_u32_le(pcap_stream, static_cast<uint32_t>(pkt3.size()));
    pcap_stream.write(reinterpret_cast<const char*>(pkt3.data()), pkt3.size());

    // Ingest with RuleEngine
    auto engine = std::make_shared<RuleEngine>();
    Rule r_telnet;
    r_telnet.id = 1;
    r_telnet.name = "Block Telnet";
    r_telnet.priority = 10;
    r_telnet.action = RuleAction::Block;
    r_telnet.dst_port_range = "23";
    engine->add_rule(r_telnet);

    Rule r_ad;
    r_ad.id = 2;
    r_ad.name = "Block Ads";
    r_ad.priority = 20;
    r_ad.action = RuleAction::Block;
    r_ad.domain_pattern = "doubleclick.net";
    engine->add_rule(r_ad);

    FlowTable flow_table;
    flow_table.set_rule_engine(engine);

    PcapReader reader;
    assert(reader.open(pcap_stream) == PcapErrorCode::Success);

    PacketRecord rec;
    size_t blocked_count = 0;
    size_t allowed_count = 0;

    while (reader.read_next_packet(rec) == PcapErrorCode::Success) {
        ParsedPacket parsed = ProtocolParser::parse(rec);
        assert(parsed.is_valid());
        auto flow = flow_table.process_packet(rec, parsed, reader.global_header().is_nanosecond_resolution);
        assert(flow != nullptr);

        if (flow->is_blocked()) {
            ++blocked_count;
        } else if (flow->policy_verdict().is_allowed()) {
            ++allowed_count;
        }
    }

    assert(blocked_count == 2); // Telnet and DoubleClick blocked
    assert(allowed_count == 1); // GitHub allowed
}

int main() {
    std::cout << "========================================\n";
    std::cout << "  Stage 5 Rule & Policy Engine Tests    \n";
    std::cout << "========================================\n";

    test_ip_matching();
    test_port_matching();
    test_domain_matching();
    test_json_rule_parsing();
    test_priority_and_deterministic_resolution();
    test_l3_l4_vs_l7_lifecycle();
    test_end_to_end_pcap_policy_pipeline();

    std::cout << "All Stage 5 Rule & Policy Engine tests PASSED!\n";
    return 0;
}
