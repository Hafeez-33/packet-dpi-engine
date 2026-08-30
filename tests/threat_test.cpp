#include "dpi/threat/entropy_calculator.h"
#include "dpi/threat/port_scan_detector.h"
#include "dpi/threat/syn_flood_detector.h"
#include "dpi/threat/dns_anomaly_detector.h"
#include "dpi/threat/payload_signature_matcher.h"
#include "dpi/threat/bounded_alert_buffer.h"
#include "dpi/threat/threat_engine.h"
#include "dpi/protocols/protocol_parser.h"
#include <cassert>
#include <cmath>
#include <iostream>
#include <string>
#include <vector>

using namespace dpi;

static std::vector<uint8_t> create_synthetic_tcp_packet(const std::string& src_ip_str,
                                                        const std::string& dst_ip_str,
                                                        uint16_t src_port,
                                                        uint16_t dst_port,
                                                        bool syn,
                                                        bool ack,
                                                        const std::string& payload = "") {
    std::vector<uint8_t> pkt;
    // Ethernet Header (14 bytes)
    for (int i = 0; i < 12; ++i) pkt.push_back(0x00);
    pkt.push_back(0x08); pkt.push_back(0x00); // IPv4

    // IPv4 Header (20 bytes)
    pkt.push_back(0x45); // Version 4, IHL 5
    pkt.push_back(0x00); // DSCP/ECN
    uint16_t total_len = 20 + 20 + static_cast<uint16_t>(payload.size());
    pkt.push_back(static_cast<uint8_t>(total_len >> 8));
    pkt.push_back(static_cast<uint8_t>(total_len & 0xFF));
    pkt.push_back(0x12); pkt.push_back(0x34); // ID
    pkt.push_back(0x40); pkt.push_back(0x00); // Flags: DF
    pkt.push_back(64);   // TTL
    pkt.push_back(6);    // TCP
    pkt.push_back(0x00); pkt.push_back(0x00); // Checksum

    auto s_opt = IPv4Address::from_string(src_ip_str);
    auto d_opt = IPv4Address::from_string(dst_ip_str);
    assert(s_opt.has_value() && d_opt.has_value());
    pkt.insert(pkt.end(), s_opt->bytes.begin(), s_opt->bytes.end());
    pkt.insert(pkt.end(), d_opt->bytes.begin(), d_opt->bytes.end());

    // TCP Header (20 bytes)
    pkt.push_back(static_cast<uint8_t>(src_port >> 8));
    pkt.push_back(static_cast<uint8_t>(src_port & 0xFF));
    pkt.push_back(static_cast<uint8_t>(dst_port >> 8));
    pkt.push_back(static_cast<uint8_t>(dst_port & 0xFF));
    pkt.push_back(0x00); pkt.push_back(0x00); pkt.push_back(0x00); pkt.push_back(0x01); // Seq
    pkt.push_back(0x00); pkt.push_back(0x00); pkt.push_back(0x00); pkt.push_back(0x02); // Ack
    pkt.push_back(0x50); // Data offset = 5 (20 bytes)

    uint8_t flags = 0;
    if (syn) flags |= 0x02;
    if (ack) flags |= 0x10;
    pkt.push_back(flags);

    pkt.push_back(0x10); pkt.push_back(0x00); // Window size
    pkt.push_back(0x00); pkt.push_back(0x00); // Checksum
    pkt.push_back(0x00); pkt.push_back(0x00); // Urgent pointer

    // Payload
    pkt.insert(pkt.end(), payload.begin(), payload.end());
    return pkt;
}

void test_shannon_entropy() {
    std::cout << "[TEST] Running test_shannon_entropy()...\n";

    // 1. Single repeated character -> entropy = 0
    double zero_entropy = EntropyCalculator::calculate_shannon_entropy("aaaaaaaaaaaa");
    assert(std::abs(zero_entropy - 0.0) < 0.001);

    // 2. Uniform 2-char string -> entropy = 1.0 bit
    double bit_entropy = EntropyCalculator::calculate_shannon_entropy("abababababab");
    assert(std::abs(bit_entropy - 1.0) < 0.001);

    // 3. High entropy base64 string
    std::string high_entropy_str = "x8F2qZ91vK7LmP0QwRtYuIoPaSdFgHjK";
    double high_entropy = EntropyCalculator::calculate_shannon_entropy(high_entropy_str);
    assert(high_entropy > 4.5);

    std::cout << "  -> PASSED (Zero=" << zero_entropy << ", Binary=" << bit_entropy << ", High=" << high_entropy << ")\n";
}

void test_vertical_port_scan() {
    std::cout << "[TEST] Running test_vertical_port_scan()...\n";

    PortScanConfig cfg;
    cfg.vertical_port_threshold = 10;
    cfg.window_us = 5000000;
    PortScanDetector detector(cfg);

    SecurityAlert alert;
    bool triggered = false;

    for (uint16_t port = 1000; port < 1015; ++port) {
        auto bytes = create_synthetic_tcp_packet("192.168.1.50", "10.0.0.1", 54321, port, true, false);
        PacketRecord rec;
        rec.payload = bytes;
        rec.header.incl_len = static_cast<uint32_t>(bytes.size());
        rec.header.orig_len = static_cast<uint32_t>(bytes.size());

        ParsedPacket parsed = ProtocolParser::parse(rec);
        assert(parsed.is_valid());

        if (detector.check_packet(parsed, 1000000 + port * 1000, alert)) {
            triggered = true;
            assert(alert.category == ThreatCategory::PortScan);
            assert(alert.src_ip.to_string() == "192.168.1.50");
            assert(alert.dst_ip.to_string() == "10.0.0.1");
            break;
        }
    }

    assert(triggered);
    std::cout << "  -> PASSED (Vertical port scan alert triggered successfully)\n";
}

void test_horizontal_port_scan() {
    std::cout << "[TEST] Running test_horizontal_port_scan()...\n";

    PortScanConfig cfg;
    cfg.horizontal_host_threshold = 10;
    cfg.window_us = 5000000;
    PortScanDetector detector(cfg);

    SecurityAlert alert;
    bool triggered = false;

    for (int i = 1; i <= 15; ++i) {
        std::string dst = "10.0.0." + std::to_string(i);
        auto bytes = create_synthetic_tcp_packet("192.168.1.50", dst, 54321, 80, true, false);
        PacketRecord rec;
        rec.payload = bytes;
        rec.header.incl_len = static_cast<uint32_t>(bytes.size());
        rec.header.orig_len = static_cast<uint32_t>(bytes.size());

        ParsedPacket parsed = ProtocolParser::parse(rec);
        assert(parsed.is_valid());

        if (detector.check_packet(parsed, 1000000 + i * 1000, alert)) {
            triggered = true;
            assert(alert.category == ThreatCategory::PortScan);
            assert(alert.src_ip.to_string() == "192.168.1.50");
            assert(alert.dst_port == 80);
            break;
        }
    }

    assert(triggered);
    std::cout << "  -> PASSED (Horizontal port scan sweep triggered successfully)\n";
}

void test_syn_flood_and_completion() {
    std::cout << "[TEST] Running test_syn_flood_and_completion()...\n";

    SynFloodConfig cfg;
    cfg.half_open_threshold = 10;
    cfg.syn_rate_threshold = 15;
    cfg.window_us = 2000000;
    cfg.half_open_timeout_us = 5000000;
    SynFloodDetector detector(cfg);

    SecurityAlert alert;
    bool triggered = false;

    // 1. Normal completed connections should not trigger SYN flood
    for (uint16_t p = 2000; p < 2005; ++p) {
        auto syn_bytes = create_synthetic_tcp_packet("192.168.1.99", "10.0.0.5", p, 443, true, false);
        PacketRecord rec1; rec1.payload = syn_bytes; rec1.header.incl_len = syn_bytes.size();
        ParsedPacket parsed_syn = ProtocolParser::parse(rec1);
        detector.check_packet(parsed_syn, 1000000, alert);

        // Handshake completion (ACK)
        auto ack_bytes = create_synthetic_tcp_packet("192.168.1.99", "10.0.0.5", p, 443, false, true);
        PacketRecord rec2; rec2.payload = ack_bytes; rec2.header.incl_len = ack_bytes.size();
        ParsedPacket parsed_ack = ProtocolParser::parse(rec2);
        detector.check_packet(parsed_ack, 1000100, alert);
    }

    // 2. Unacknowledged SYN burst
    for (uint16_t p = 3000; p < 3015; ++p) {
        auto syn_bytes = create_synthetic_tcp_packet("192.168.1.99", "10.0.0.5", p, 443, true, false);
        PacketRecord rec; rec.payload = syn_bytes; rec.header.incl_len = syn_bytes.size();
        ParsedPacket parsed = ProtocolParser::parse(rec);

        if (detector.check_packet(parsed, 1000200 + p * 10, alert)) {
            triggered = true;
            assert(alert.category == ThreatCategory::SynFlood);
            assert(alert.severity == AlertSeverity::Critical);
            break;
        }
    }

    assert(triggered);
    std::cout << "  -> PASSED (SYN Flood detected on unacknowledged half-open accumulation)\n";
}

void test_dns_anomalies() {
    std::cout << "[TEST] Running test_dns_anomalies()...\n";

    DnsAnomalyConfig cfg;
    cfg.max_entropy_threshold = 3.8;
    cfg.max_label_length = 30;
    cfg.max_fqdn_length = 80;
    DnsAnomalyDetector detector(cfg);

    auto pkt_bytes = create_synthetic_tcp_packet("192.168.1.10", "8.8.8.8", 12345, 53, false, false);
    PacketRecord rec; rec.payload = pkt_bytes; rec.header.incl_len = pkt_bytes.size();
    ParsedPacket parsed = ProtocolParser::parse(rec);

    SecurityAlert alert;

    // Normal domain
    assert(!detector.check_dns_query("www.google.com", parsed, 1000, alert));

    // High-entropy tunneling domain (DGA / Data exfiltration)
    bool entropy_hit = detector.check_dns_query("v9x8b7c6d5e4f3a2z1q0.tunnel.evil.com", parsed, 1000, alert);
    assert(entropy_hit);
    assert(alert.category == ThreatCategory::DnsDgaAnomaly);

    // Overly long label
    std::string long_label_domain = "thislabeliswaytoolongtooccurinnormaltrafficexceedingthirtychars.evil.com";
    bool length_hit = detector.check_dns_query(long_label_domain, parsed, 1000, alert);
    assert(length_hit);
    assert(alert.category == ThreatCategory::DnsTunneling);

    std::cout << "  -> PASSED (DNS high-entropy & label length heuristics verified)\n";
}

void test_payload_signatures() {
    std::cout << "[TEST] Running test_payload_signatures()...\n";

    PayloadSignatureMatcher matcher;
    matcher.load_default_signatures();

    SecurityAlert alert;
    L7Metadata meta;

    // 1. Test SQL Injection matching in payload
    std::string sqli_payload = "GET /search?id=1 UNION SELECT username,password FROM users HTTP/1.1\r\nHost: target.com\r\n\r\n";
    auto pkt1 = create_synthetic_tcp_packet("192.168.1.20", "10.0.0.2", 45000, 80, false, false, sqli_payload);
    PacketRecord rec1; rec1.payload = pkt1; rec1.header.incl_len = pkt1.size();
    ParsedPacket parsed1 = ProtocolParser::parse(rec1);

    bool sqli_hit = matcher.match(parsed1, meta, reinterpret_cast<const uint8_t*>(parsed1.l7_payload.data()), parsed1.l7_payload.size(), 1000, alert);
    assert(sqli_hit);
    assert(alert.category == ThreatCategory::SqlInjection);
    assert(alert.signature_name.find("UNION SELECT") != std::string::npos);

    // 2. Test Path Traversal in URI
    meta.protocol = AppProtocol::HTTP;
    meta.http.uri = "/download?file=../../../../etc/passwd";

    std::string traversal_payload = "GET /download?file=../../../../etc/passwd HTTP/1.1\r\nHost: target.com\r\n\r\n";
    auto pkt2 = create_synthetic_tcp_packet("192.168.1.20", "10.0.0.2", 45001, 80, false, false, traversal_payload);
    PacketRecord rec2; rec2.payload = pkt2; rec2.header.incl_len = pkt2.size();
    ParsedPacket parsed2 = ProtocolParser::parse(rec2);

    bool trav_hit = matcher.match(parsed2, meta, reinterpret_cast<const uint8_t*>(parsed2.l7_payload.data()), parsed2.l7_payload.size(), 1000, alert);
    assert(trav_hit);
    assert(alert.category == ThreatCategory::DirectoryTraversal);

    // 3. Test Scanner User-Agent in payload
    L7Metadata meta3;
    std::string ua_payload = "GET /index.html HTTP/1.1\r\nHost: target.com\r\nUser-Agent: sqlmap/1.6\r\n\r\n";
    auto pkt3 = create_synthetic_tcp_packet("192.168.1.20", "10.0.0.2", 45002, 80, false, false, ua_payload);
    PacketRecord rec3; rec3.payload = pkt3; rec3.header.incl_len = pkt3.size();
    ParsedPacket parsed3 = ProtocolParser::parse(rec3);

    bool ua_hit = matcher.match(parsed3, meta3, reinterpret_cast<const uint8_t*>(parsed3.l7_payload.data()), parsed3.l7_payload.size(), 1000, alert);
    assert(ua_hit);
    assert(alert.category == ThreatCategory::SuspiciousUserAgent);

    std::cout << "  -> PASSED (SQLi, Directory Traversal, and Scanner User-Agent signatures matched)\n";
}

void test_bounded_alert_buffer() {
    std::cout << "[TEST] Running test_bounded_alert_buffer()...\n";

    BoundedAlertBuffer buffer(5);
    assert(buffer.capacity() == 5);
    assert(buffer.size() == 0);
    assert(buffer.dropped_count() == 0);

    for (uint64_t i = 1; i <= 8; ++i) {
        SecurityAlert a;
        a.alert_id = i;
        a.signature_name = "Alert #" + std::to_string(i);
        buffer.push(a);
    }

    assert(buffer.size() == 5);
    assert(buffer.dropped_count() == 3); // 8 - 5 = 3 dropped
    assert(buffer.total_generated_count() == 8);

    auto snapshot = buffer.get_snapshot();
    assert(snapshot.size() == 5);
    // Should retain alerts 4, 5, 6, 7, 8
    assert(snapshot[0].alert_id == 4);
    assert(snapshot[4].alert_id == 8);

    std::cout << "  -> PASSED (Bounded ring buffer overflow drops and retention verified)\n";
}

int main() {
    std::cout << "========================================\n";
    std::cout << "  Stage 8: Threat & Anomaly Test Suite  \n";
    std::cout << "========================================\n";

    test_shannon_entropy();
    test_vertical_port_scan();
    test_horizontal_port_scan();
    test_syn_flood_and_completion();
    test_dns_anomalies();
    test_payload_signatures();
    test_bounded_alert_buffer();

    std::cout << "========================================\n";
    std::cout << "  ALL STAGE 8 THREAT TESTS PASSED (100%)\n";
    std::cout << "========================================\n";
    return 0;
}
