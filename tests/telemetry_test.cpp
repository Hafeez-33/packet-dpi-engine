#include "dpi/packet/pcap_reader.h"
#include "dpi/pipeline/worker_pool.h"
#include "dpi/rules/rule_engine.h"
#include "dpi/telemetry/telemetry_collector.h"
#include <cassert>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>
#include <vector>

using namespace dpi;

static void push_u16_be(std::vector<uint8_t>& buf, uint16_t val) {
    buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

static void push_u32_be(std::vector<uint8_t>& buf, uint32_t val) {
    buf.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

static std::vector<uint8_t> make_packet(uint32_t src_ip, uint16_t src_port,
                                        uint32_t dst_ip, uint16_t dst_port,
                                        uint8_t proto,
                                        const std::string& payload = "") {
    std::vector<uint8_t> pkt;
    // Ethernet
    for (int i = 0; i < 12; ++i) pkt.push_back(0);
    push_u16_be(pkt, ethertype::IPV4);

    // IPv4
    uint16_t l4_hdr_len = (proto == ipproto::TCP) ? 20 : 8;
    uint16_t ip_len = static_cast<uint16_t>(20 + l4_hdr_len + payload.size());
    pkt.push_back(0x45);
    pkt.push_back(0x00);
    push_u16_be(pkt, ip_len);
    push_u16_be(pkt, 0x1234);
    push_u16_be(pkt, 0x4000);
    pkt.push_back(64);
    pkt.push_back(proto);
    push_u16_be(pkt, 0);
    push_u32_be(pkt, src_ip);
    push_u32_be(pkt, dst_ip);

    if (proto == ipproto::TCP) {
        push_u16_be(pkt, src_port);
        push_u16_be(pkt, dst_port);
        push_u32_be(pkt, 100);
        push_u32_be(pkt, 0);
        push_u16_be(pkt, (5u << 12) | 0x18);
        push_u16_be(pkt, 65535);
        push_u16_be(pkt, 0);
        push_u16_be(pkt, 0);
    } else {
        push_u16_be(pkt, src_port);
        push_u16_be(pkt, dst_port);
        push_u16_be(pkt, static_cast<uint16_t>(8 + payload.size()));
        push_u16_be(pkt, 0);
    }

    pkt.insert(pkt.end(), payload.begin(), payload.end());
    return pkt;
}

void test_telemetry_snapshot_counters() {
    std::cout << "[TEST] Telemetry Snapshot Counter Accuracy..." << std::endl;

    WorkerConfig config;
    config.num_workers = 2;
    WorkerPool pool(config);
    pool.start();

    TelemetryCollector collector(pool);
    collector.set_status(EngineStatus::Running);

    for (size_t i = 0; i < 100; ++i) {
        auto pkt = make_packet(0x0A000001 + static_cast<uint32_t>(i % 10), 1000 + static_cast<uint16_t>(i % 10),
                               0x0B000001, 80, ipproto::TCP, "DATA");
        PacketRecord rec;
        rec.payload = pkt;
        pool.dispatch(std::move(rec));
    }

    pool.stop();
    collector.set_status(EngineStatus::Completed);

    TelemetrySnapshot snap = collector.capture_snapshot();
    assert(snap.status == EngineStatus::Completed);
    assert(snap.total_packets == 100);
    assert(snap.total_flows == 10);
    assert(snap.tcp_flows == 10);
    assert(snap.udp_flows == 0);
    assert(snap.worker_stats.size() == 2);
}

void test_atomic_json_file_export_and_replacement() {
    std::cout << "[TEST] Atomic JSON Snapshot File Replacement..." << std::endl;

    std::string test_file = "test_telemetry_output.json";
    std::filesystem::remove(test_file);
    std::filesystem::remove(test_file + ".tmp");

    WorkerConfig config;
    config.num_workers = 2;
    WorkerPool pool(config);
    pool.start();

    TelemetryCollector collector(pool);
    collector.set_status(EngineStatus::Running);

    // Initial write
    assert(collector.export_json_atomic(test_file));
    assert(std::filesystem::exists(test_file));
    assert(!std::filesystem::exists(test_file + ".tmp"));

    // Verify valid JSON readable
    {
        std::ifstream ifs(test_file);
        std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
        assert(content.find("\"engine_status\": \"ENGINE_RUNNING\"") != std::string::npos);
        assert(content.find("\"traffic\": {") != std::string::npos);
    }

    // Update and replace atomically
    collector.set_status(EngineStatus::Completed);
    assert(collector.export_json_atomic(test_file));

    {
        std::ifstream ifs2(test_file);
        std::string content2((std::istreambuf_iterator<char>(ifs2)), std::istreambuf_iterator<char>());
        assert(content2.find("\"engine_status\": \"ENGINE_COMPLETED\"") != std::string::npos);
    }

    pool.stop();
    std::filesystem::remove(test_file);
}

void test_protocol_and_dpi_breakdown() {
    std::cout << "[TEST] Protocol & DPI Telemetry Breakdown..." << std::endl;

    WorkerConfig config;
    config.num_workers = 2;
    WorkerPool pool(config);
    pool.start();

    TelemetryCollector collector(pool);

    // 1. HTTP
    std::string http_payload = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    auto pkt_http = make_packet(0x0A000001, 10001, 0x0A000002, 80, ipproto::TCP, http_payload);
    PacketRecord r1; r1.payload = pkt_http;
    pool.dispatch(std::move(r1));

    // 2. DNS
    std::vector<uint8_t> dns_payload{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x03, 'w', 'w', 'w',
        0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm',
        0x00, 0x00, 0x01, 0x00, 0x01
    };
    std::string dns_str(dns_payload.begin(), dns_payload.end());
    auto pkt_dns = make_packet(0x0A000003, 10002, 0x08080808, 53, ipproto::UDP, dns_str);
    PacketRecord r2; r2.payload = pkt_dns;
    pool.dispatch(std::move(r2));

    pool.stop();

    TelemetrySnapshot snap = collector.capture_snapshot();
    assert(snap.total_flows == 2);
    assert(snap.tcp_flows == 1);
    assert(snap.udp_flows == 1);
    assert(snap.http_flows == 1);
    assert(snap.dns_flows == 1);
}

void test_policy_verdict_telemetry() {
    std::cout << "[TEST] Policy Verdict Telemetry Export..." << std::endl;

    auto rule_engine = std::make_shared<RuleEngine>();
    Rule r1;
    r1.id = 1;
    r1.name = "Block Port 8080";
    r1.priority = 10;
    r1.action = RuleAction::Block;
    r1.dst_port_range = "8080";
    rule_engine->add_rule(r1);

    WorkerConfig config;
    config.num_workers = 2;
    WorkerPool pool(config, rule_engine);
    pool.start();

    TelemetryCollector collector(pool);

    // Blocked flow
    auto pkt_blocked = make_packet(0x0A000001, 10001, 0x0A000002, 8080, ipproto::TCP, "HELLO");
    PacketRecord rec1; rec1.payload = pkt_blocked;
    pool.dispatch(std::move(rec1));

    // Allowed flow
    auto pkt_allowed = make_packet(0x0A000001, 10002, 0x0A000003, 80, ipproto::TCP, "HELLO");
    PacketRecord rec2; rec2.payload = pkt_allowed;
    pool.dispatch(std::move(rec2));

    pool.stop();

    TelemetrySnapshot snap = collector.capture_snapshot();
    assert(snap.total_flows == 2);
    assert(snap.blocked_packets == 1);
    assert(snap.blocked_flows == 1);
    assert(snap.allowed_flows == 1);

    bool found_blocked = false;
    for (const auto& f : snap.flows) {
        if (f.dst_port == 8080) {
            assert(f.is_blocked);
            assert(f.policy_verdict == "BLOCK");
            assert(f.matched_rule_name == "Block Port 8080");
            found_blocked = true;
        }
    }
    assert(found_blocked);
}

void test_bounded_flow_limit() {
    std::cout << "[TEST] Bounded Flow Records Telemetry Limit..." << std::endl;

    WorkerConfig config;
    config.num_workers = 2;
    WorkerPool pool(config);
    pool.start();

    // Create 50 distinct flows
    for (size_t i = 0; i < 50; ++i) {
        auto pkt = make_packet(0x0A000000 + static_cast<uint32_t>(i), 10000 + static_cast<uint16_t>(i),
                               0x0B000000, 80, ipproto::TCP);
        PacketRecord rec; rec.payload = pkt;
        pool.dispatch(std::move(rec));
    }

    pool.stop();

    // Set max flows limit to 15
    TelemetryCollector collector(pool, 15);
    TelemetrySnapshot snap = collector.capture_snapshot();
    assert(snap.total_flows == 50); // Global counter has all 50
    assert(snap.flows.size() == 15); // Detailed list bounded to exactly 15
}

void test_concurrent_snapshot_safety() {
    std::cout << "[TEST] Concurrent Snapshot Thread-Safety..." << std::endl;

    WorkerConfig config;
    config.num_workers = 4;
    config.queue_capacity = 2048;
    WorkerPool pool(config);
    pool.start();

    TelemetryCollector collector(pool, 500);

    std::atomic<bool> producer_done{false};

    // Background thread continuously capturing snapshots
    std::thread snapshot_reader([&]() {
        while (!producer_done.load()) {
            TelemetrySnapshot s = collector.capture_snapshot();
            assert(s.worker_stats.size() == 4);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    });

    // Producer dispatching 2,000 packets
    for (size_t i = 0; i < 2000; ++i) {
        uint32_t flow_idx = static_cast<uint32_t>(i % 50);
        auto pkt = make_packet(0x0A000000 + flow_idx, 10000 + static_cast<uint16_t>(flow_idx),
                               0x0B000000, 80, ipproto::TCP, "PAYLOAD");
        PacketRecord rec; rec.payload = pkt;
        pool.dispatch(std::move(rec));
    }

    producer_done = true;
    snapshot_reader.join();
    pool.stop();

    TelemetrySnapshot final_snap = collector.capture_snapshot();
    assert(final_snap.total_packets == 2000);
}

int main() {
    std::cout << "========================================\n";
    std::cout << "     Stage 7 Telemetry Unit Tests       \n";
    std::cout << "========================================\n";

    test_telemetry_snapshot_counters();
    test_atomic_json_file_export_and_replacement();
    test_protocol_and_dpi_breakdown();
    test_policy_verdict_telemetry();
    test_bounded_flow_limit();
    test_concurrent_snapshot_safety();

    std::cout << "All Stage 7 Telemetry tests PASSED!\n";
    return 0;
}
