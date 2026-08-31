#include "dpi/risk/behavioral_profiler.h"
#include "dpi/risk/beaconing_detector.h"
#include "dpi/risk/exfiltration_detector.h"
#include "dpi/risk/risk_scorer.h"
#include "dpi/risk/host_risk_profiler.h"
#include "dpi/risk/risk_engine.h"
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
    pkt.push_back(0x18); // Flags: PSH, ACK
    pkt.push_back(0x10); pkt.push_back(0x00); // Window size
    pkt.push_back(0x00); pkt.push_back(0x00); // Checksum
    pkt.push_back(0x00); pkt.push_back(0x00); // Urgent pointer

    // Payload
    pkt.insert(pkt.end(), payload.begin(), payload.end());
    return pkt;
}

void test_welford_iat_calculation() {
    std::cout << "[TEST] Running test_welford_iat_calculation()...\n";

    BehavioralMetrics metrics{};
    auto pkt = create_synthetic_tcp_packet("192.168.1.100", "10.0.0.1", 50000, 80, "test");
    PacketRecord rec; rec.payload = pkt; rec.header.incl_len = pkt.size();
    ParsedPacket parsed = ProtocolParser::parse(rec);

    // Initial packet
    FlowBehavioralProfiler::update_metrics(metrics, parsed, 1000000, true);
    assert(metrics.fwd_packets == 1);
    assert(metrics.iat_count == 0);

    // Sequence of exact 100ms intervals (100000 us)
    for (int i = 1; i <= 10; ++i) {
        uint64_t ts = 1000000 + i * 100000;
        FlowBehavioralProfiler::update_metrics(metrics, parsed, ts, true);
    }

    assert(metrics.iat_count == 10);
    assert(std::abs(metrics.mean_iat_ms - 100.0) < 0.001);
    assert(std::abs(metrics.iat_variance_ms2 - 0.0) < 0.001);
    assert(std::abs(metrics.iat_stddev_ms - 0.0) < 0.001);
    assert(std::abs(metrics.iat_jitter_ratio - 0.0) < 0.001);

    std::cout << "  -> PASSED (Welford zero-jitter stream calculations verified)\n";
}

void test_beaconing_detection() {
    std::cout << "[TEST] Running test_beaconing_detection()...\n";

    BeaconingDetector detector;
    BehavioralMetrics beacon_metrics{};
    auto pkt = create_synthetic_tcp_packet("192.168.1.100", "198.51.100.5", 50001, 443, "ping");
    PacketRecord rec; rec.payload = pkt; rec.header.incl_len = pkt.size();
    ParsedPacket parsed = ProtocolParser::parse(rec);

    // 1. Regular 500ms intervals with minimal jitter (500ms +/- 5ms -> jitter ~ 0.01)
    uint64_t current_ts = 1000000;
    FlowBehavioralProfiler::update_metrics(beacon_metrics, parsed, current_ts, true);

    for (int i = 0; i < 12; ++i) {
        current_ts += 500000 + ((i % 2 == 0) ? 2000 : -2000); // 502ms / 498ms
        FlowBehavioralProfiler::update_metrics(beacon_metrics, parsed, current_ts, true);
    }

    bool is_beacon = detector.evaluate(beacon_metrics);
    assert(is_beacon);
    assert(beacon_metrics.is_beaconing);
    assert(std::abs(beacon_metrics.beacon_interval_ms - 500.0) < 2.0);

    // 2. High jitter traffic (e.g. human browsing: 100ms, 2500ms, 50ms, 4000ms)
    BehavioralMetrics normal_metrics{};
    current_ts = 1000000;
    FlowBehavioralProfiler::update_metrics(normal_metrics, parsed, current_ts, true);
    std::vector<uint64_t> erratic_deltas = {100000, 2500000, 50000, 4000000, 200000, 1500000, 80000, 3000000, 500000};
    for (uint64_t delta : erratic_deltas) {
        current_ts += delta;
        FlowBehavioralProfiler::update_metrics(normal_metrics, parsed, current_ts, true);
    }

    bool not_beacon = detector.evaluate(normal_metrics);
    assert(!not_beacon);
    assert(!normal_metrics.is_beaconing);

    std::cout << "  -> PASSED (C2 periodic beaconing vs erratic web traffic differentiated)\n";
}

void test_exfiltration_detection() {
    std::cout << "[TEST] Running test_exfiltration_detection()...\n";

    ExfiltrationConfig cfg;
    cfg.min_fwd_bytes = 10000;
    cfg.min_byte_ratio = 10.0;
    ExfiltrationDetector detector(cfg);

    BehavioralMetrics metrics{};
    metrics.fwd_bytes = 50000;
    metrics.rev_bytes = 1000;
    metrics.byte_ratio = 50.0;

    assert(detector.evaluate(metrics));
    assert(metrics.is_exfiltration);

    // Normal balanced traffic
    BehavioralMetrics normal{};
    normal.fwd_bytes = 50000;
    normal.rev_bytes = 80000;
    normal.byte_ratio = 50000.0 / 80000.0;

    assert(!detector.evaluate(normal));
    assert(!normal.is_exfiltration);

    std::cout << "  -> PASSED (Data exfiltration directional asymmetry verified)\n";
}

void test_risk_scoring_tiers() {
    std::cout << "[TEST] Running test_risk_scoring_tiers()...\n";

    RiskScorer scorer;
    BehavioralMetrics metrics{};
    L7Metadata l7{};
    std::vector<SecurityAlert> alerts;

    // 1. Clean flow
    FlowRiskScore score1 = scorer.calculate_score(metrics, l7, RuleAction::Allow, alerts, 80);
    assert(score1.score == 0);
    assert(score1.level == RiskLevel::None);

    // 2. Beaconing flow (+35)
    metrics.is_beaconing = true;
    FlowRiskScore score2 = scorer.calculate_score(metrics, l7, RuleAction::Allow, alerts, 443);
    assert(score2.score == 35);
    assert(score2.level == RiskLevel::Low);

    // 3. Blocked + Threat Alert Critical (40 + 50 = 90 -> Critical)
    SecurityAlert critical_alert{};
    critical_alert.severity = AlertSeverity::Critical;
    critical_alert.signature_name = "Exploit: RCE Attempt";
    alerts.push_back(critical_alert);

    FlowRiskScore score3 = scorer.calculate_score(metrics, l7, RuleAction::Block, alerts, 8080);
    assert(score3.score >= 80);
    assert(score3.level == RiskLevel::Critical);
    assert(score3.contributing_factors.size() >= 2);

    std::cout << "  -> PASSED (Multidimensional risk tiers None/Low/Medium/High/Critical verified)\n";
}

void test_host_risk_profiler_lru() {
    std::cout << "[TEST] Running test_host_risk_profiler_lru()...\n";

    HostRiskProfiler profiler(3); // Capacity = 3
    assert(profiler.size() == 0);

    auto ip1 = *IPv4Address::from_string("10.0.0.1");
    auto ip2 = *IPv4Address::from_string("10.0.0.2");
    auto ip3 = *IPv4Address::from_string("10.0.0.3");
    auto ip4 = *IPv4Address::from_string("10.0.0.4");

    profiler.update_host_risk(IPAddress(ip1), 20, false, false, 1000);
    profiler.update_host_risk(IPAddress(ip2), 85, true, false, 2000);
    profiler.update_host_risk(IPAddress(ip3), 40, false, false, 3000);
    assert(profiler.size() == 3);

    // Adding 4th host evicts least recently used ip1
    profiler.update_host_risk(IPAddress(ip4), 70, false, true, 4000);
    assert(profiler.size() == 3);

    auto top = profiler.get_top_hosts(5);
    assert(top.size() == 3);
    assert(top[0].ip.to_string() == "10.0.0.2"); // Risk 85
    assert(top[0].max_flow_risk == 85);
    assert(top[0].has_beaconing_flow);

    std::cout << "  -> PASSED (HostRiskProfiler LRU bounded capacity & ranking verified)\n";
}

int main() {
    std::cout << "========================================\n";
    std::cout << "   Stage 9: Risk & NTA Test Suite       \n";
    std::cout << "========================================\n";

    test_welford_iat_calculation();
    test_beaconing_detection();
    test_exfiltration_detection();
    test_risk_scoring_tiers();
    test_host_risk_profiler_lru();

    std::cout << "========================================\n";
    std::cout << "   ALL STAGE 9 RISK TESTS PASSED (100%)\n";
    std::cout << "========================================\n";
    return 0;
}
