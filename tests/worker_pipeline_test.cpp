#include "dpi/packet/pcap_reader.h"
#include "dpi/pipeline/bounded_queue.h"
#include "dpi/pipeline/flow_router.h"
#include "dpi/pipeline/worker_pool.h"
#include "dpi/protocols/protocol_parser.h"
#include "dpi/rules/rule_engine.h"
#include <cassert>
#include <chrono>
#include <iostream>
#include <sstream>
#include <thread>
#include <vector>

using namespace dpi;

// -------------------------------------------------------------
// Test Helpers & Packet Synthesizers
// -------------------------------------------------------------

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

static std::vector<uint8_t> make_ipv4_tcp_packet(uint32_t src_ip, uint16_t src_port,
                                                 uint32_t dst_ip, uint16_t dst_port,
                                                 uint32_t seq, uint32_t ack,
                                                 uint8_t flags_byte,
                                                 const std::string& payload = "") {
    std::vector<uint8_t> pkt;
    // Ethernet
    for (int i = 0; i < 12; ++i) pkt.push_back(0);
    push_u16_be(pkt, ethertype::IPV4);

    // IPv4
    uint16_t ip_len = static_cast<uint16_t>(20 + 20 + payload.size());
    pkt.push_back(0x45);
    pkt.push_back(0x00);
    push_u16_be(pkt, ip_len);
    push_u16_be(pkt, 0x1234);
    push_u16_be(pkt, 0x4000);
    pkt.push_back(64);
    pkt.push_back(ipproto::TCP);
    push_u16_be(pkt, 0);
    push_u32_be(pkt, src_ip);
    push_u32_be(pkt, dst_ip);

    // TCP
    push_u16_be(pkt, src_port);
    push_u16_be(pkt, dst_port);
    push_u32_be(pkt, seq);
    push_u32_be(pkt, ack);
    push_u16_be(pkt, (5u << 12) | flags_byte);
    push_u16_be(pkt, 65535);
    push_u16_be(pkt, 0);
    push_u16_be(pkt, 0);

    pkt.insert(pkt.end(), payload.begin(), payload.end());
    return pkt;
}

static std::string make_synthetic_pcap_stream(const std::vector<std::vector<uint8_t>>& packets) {
    std::stringstream ss(std::ios::in | std::ios::out | std::ios::binary);

    auto write_u32_le = [](std::ostream& os, uint32_t val) {
        os.write(reinterpret_cast<const char*>(&val), sizeof(val));
    };
    auto write_u16_le = [](std::ostream& os, uint16_t val) {
        os.write(reinterpret_cast<const char*>(&val), sizeof(val));
    };

    // Global Header
    write_u32_le(ss, pcap_magic::MICROSEC_NATIVE);
    write_u16_le(ss, 2);
    write_u16_le(ss, 4);
    write_u32_le(ss, 0);
    write_u32_le(ss, 0);
    write_u32_le(ss, 65535);
    write_u32_le(ss, 1);

    uint32_t ts_sec = 1600000000;
    uint32_t ts_usec = 1000;

    for (const auto& pkt : packets) {
        write_u32_le(ss, ts_sec);
        write_u32_le(ss, ts_usec);
        write_u32_le(ss, static_cast<uint32_t>(pkt.size()));
        write_u32_le(ss, static_cast<uint32_t>(pkt.size()));
        ss.write(reinterpret_cast<const char*>(pkt.data()), pkt.size());
        ts_usec += 1000;
    }

    return ss.str();
}

// -------------------------------------------------------------
// Test Cases
// -------------------------------------------------------------

void test_bounded_queue_basic_and_backpressure() {
    std::cout << "[TEST] BoundedQueue Basic, Backpressure, and Shutdown..." << std::endl;

    BoundedQueue<int> q(5);
    assert(q.capacity() == 5);
    assert(q.empty());
    assert(q.size() == 0);

    // Push 5 items
    for (int i = 1; i <= 5; ++i) {
        assert(q.push(i));
    }
    assert(q.size() == 5);

    // Test backpressure via thread
    std::atomic<bool> thread_pushed{false};
    std::thread producer([&]() {
        // This will block until consumer pops an item
        q.push(6);
        thread_pushed = true;
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    assert(!thread_pushed.load()); // Producer should still be blocked

    int item = 0;
    assert(q.pop(item));
    assert(item == 1);

    producer.join();
    assert(thread_pushed.load());
    assert(q.size() == 5); // 2, 3, 4, 5, 6

    // Drain and shutdown
    q.shutdown();
    int count = 0;
    while (q.pop(item)) {
        count++;
    }
    assert(count == 5);
    assert(q.empty());
    assert(!q.pop(item)); // Empty and shut down returns false
}

void test_flow_router_minimal_parse() {
    std::cout << "[TEST] FlowRouter Minimal Bounds-Checked Parse..." << std::endl;

    // 1. Valid IPv4 TCP Packet
    auto pkt1 = make_ipv4_tcp_packet(0xC0A80101, 12345, 0xC0A80102, 80, 100, 0, 0x02);
    FlowKey key1;
    assert(FlowRouter::extract_flow_key(pkt1.data(), pkt1.size(), key1));

    // 2. Reverse Direction IPv4 TCP Packet
    auto pkt2 = make_ipv4_tcp_packet(0xC0A80102, 80, 0xC0A80101, 12345, 200, 101, 0x12);
    FlowKey key2;
    assert(FlowRouter::extract_flow_key(pkt2.data(), pkt2.size(), key2));

    // Must yield the exact same canonical FlowKey!
    assert(key1 == key2);
    assert(FlowKeyHasher()(key1) == FlowKeyHasher()(key2));

    // 3. Truncated Packet Safety
    FlowKey key_bad;
    assert(!FlowRouter::extract_flow_key(pkt1.data(), 10, key_bad));
    assert(!FlowRouter::extract_flow_key(nullptr, 100, key_bad));

    // 4. Non-IP packet (ARP)
    std::vector<uint8_t> arp_pkt(28, 0);
    push_u16_be(arp_pkt, 0x0806); // EtherType ARP
    assert(!FlowRouter::extract_flow_key(arp_pkt.data(), arp_pkt.size(), key_bad));
}

void test_deterministic_flow_affinity_bidirectional() {
    std::cout << "[TEST] Deterministic Flow Affinity & Bidirectional Pinning..." << std::endl;

    WorkerConfig config;
    config.num_workers = 4;
    config.queue_capacity = 1024;

    WorkerPool pool(config);
    pool.start();

    // Create 20 bidirectional flows and dispatch forward & reverse packets
    constexpr size_t NUM_FLOWS = 20;
    for (size_t f = 0; f < NUM_FLOWS; ++f) {
        uint32_t src_ip = 0x0A000001 + static_cast<uint32_t>(f);
        uint32_t dst_ip = 0xC0A80101;
        uint16_t src_port = static_cast<uint16_t>(20000 + f);
        uint16_t dst_port = 443;

        // Forward SYN
        auto fwd = make_ipv4_tcp_packet(src_ip, src_port, dst_ip, dst_port, 100, 0, 0x02);
        PacketRecord rec_fwd;
        rec_fwd.payload = fwd;
        assert(pool.dispatch(std::move(rec_fwd)));

        // Reverse SYN-ACK
        auto rev = make_ipv4_tcp_packet(dst_ip, dst_port, src_ip, src_port, 200, 101, 0x12);
        PacketRecord rec_rev;
        rec_rev.payload = rev;
        assert(pool.dispatch(std::move(rec_rev)));
    }

    pool.stop();
    PipelineStats stats = pool.get_aggregated_stats();
    assert(stats.total_packets == NUM_FLOWS * 2);
    assert(stats.total_flows == NUM_FLOWS);

    // Verify all 4 workers received packets and each flow remained on a single worker
    uint64_t total_worker_flows = 0;
    for (const auto& ws : stats.per_worker_stats) {
        total_worker_flows += ws.flows_created;
        // Each flow received exactly 2 packets (fwd + rev)
        assert(ws.packets_processed == ws.flows_created * 2);
    }
    assert(total_worker_flows == NUM_FLOWS);
}

void test_concurrent_independent_flows() {
    std::cout << "[TEST] Concurrent Independent Flows Distribution..." << std::endl;

    WorkerConfig config;
    config.num_workers = 4;
    config.queue_capacity = 2048;

    WorkerPool pool(config);
    pool.start();

    constexpr size_t TOTAL_PACKETS = 2000;
    constexpr size_t NUM_FLOWS = 100;

    for (size_t i = 0; i < TOTAL_PACKETS; ++i) {
        uint32_t flow_idx = static_cast<uint32_t>(i % NUM_FLOWS);
        uint32_t src_ip = 0x0A000000 + (flow_idx * 17);
        uint32_t dst_ip = 0x0B000000 + (flow_idx * 31);
        uint16_t src_port = static_cast<uint16_t>(10000 + (flow_idx * 37) % 50000);
        uint16_t dst_port = (flow_idx % 2 == 0) ? 80 : 443;

        auto pkt = make_ipv4_tcp_packet(src_ip, src_port, dst_ip, dst_port, static_cast<uint32_t>(i * 10), 0, 0x18, "PING");
        PacketRecord rec;
        rec.payload = pkt;
        assert(pool.dispatch(std::move(rec)));
    }

    pool.stop();
    PipelineStats stats = pool.get_aggregated_stats();
    assert(stats.total_packets == TOTAL_PACKETS);
    assert(stats.total_flows == NUM_FLOWS);

    // Ensure all workers participated
    for (const auto& ws : stats.per_worker_stats) {
        assert(ws.packets_processed > 0);
        assert(ws.flows_created > 0);
    }
}

void test_in_order_packet_processing_per_flow() {
    std::cout << "[TEST] Strict In-Order Packet Processing per Flow..." << std::endl;

    WorkerConfig config;
    config.num_workers = 2;
    config.queue_capacity = 1024;

    WorkerPool pool(config);
    pool.start();

    // 100 packets in strict sequence for a single flow
    constexpr size_t PACKET_COUNT = 100;
    for (size_t seq = 1; seq <= PACKET_COUNT; ++seq) {
        auto pkt = make_ipv4_tcp_packet(0x0A000001, 55555, 0x0A000002, 80, static_cast<uint32_t>(seq * 100), 0, 0x10);
        PacketRecord rec;
        rec.payload = pkt;
        assert(pool.dispatch(std::move(rec)));
    }

    pool.stop();
    PipelineStats stats = pool.get_aggregated_stats();
    assert(stats.total_packets == PACKET_COUNT);
    assert(stats.total_flows == 1);
}

void test_graceful_shutdown_and_drain() {
    std::cout << "[TEST] Graceful Shutdown and Drain..." << std::endl;

    WorkerConfig config;
    config.num_workers = 2;
    config.queue_capacity = 2048;

    WorkerPool pool(config);
    pool.start();

    // Rapidly dispatch 500 packets and immediately trigger stop()
    for (size_t i = 0; i < 500; ++i) {
        auto pkt = make_ipv4_tcp_packet(0x0A000001, 1234, 0x0A000002, 80, static_cast<uint32_t>(i), 0, 0x10);
        PacketRecord rec;
        rec.payload = pkt;
        pool.dispatch(std::move(rec));
    }

    pool.stop(); // Must drain all 500 packets before joining
    PipelineStats stats = pool.get_aggregated_stats();
    assert(stats.total_packets == 500);
}

void test_edge_cases_empty_pcap_and_malformed() {
    std::cout << "[TEST] Edge Cases: Empty PCAP & Malformed Packets..." << std::endl;

    // 1. Empty PCAP
    std::string empty_pcap = make_synthetic_pcap_stream({});
    std::stringstream ss_empty(empty_pcap);
    PcapReader reader_empty;
    assert(reader_empty.open(ss_empty) == PcapErrorCode::Success);

    WorkerConfig config;
    config.num_workers = 2;
    WorkerPool pool(config);
    PipelineStats stats_empty = pool.process_pcap(reader_empty);
    assert(stats_empty.total_packets == 0);
    assert(stats_empty.total_flows == 0);

    // 2. Unroutable & Malformed Packets
    std::vector<std::vector<uint8_t>> raw_pkts;
    // Malformed packet (3 bytes)
    raw_pkts.push_back({0x01, 0x02, 0x03});
    // Non-IP packet (ARP)
    std::vector<uint8_t> arp(28, 0);
    push_u16_be(arp, 0x0806);
    raw_pkts.push_back(arp);

    std::string malformed_pcap = make_synthetic_pcap_stream(raw_pkts);
    std::stringstream ss_mal(malformed_pcap);
    PcapReader reader_mal;
    assert(reader_mal.open(ss_mal) == PcapErrorCode::Success);

    WorkerPool pool_mal(config);
    PipelineStats stats_mal = pool_mal.process_pcap(reader_mal);
    assert(stats_mal.total_packets == 0);
    assert(stats_mal.total_malformed_packets > 0 || stats_mal.unroutable_packets > 0);
}

void test_end_to_end_pcap_pipeline_with_rules_and_dpi() {
    std::cout << "[TEST] End-to-End PCAP Ingestion with DPI & RuleEngine Across Workers..." << std::endl;

    // Rules: Block port 23 (Telnet) and domain "doubleclick.net"
    auto rule_engine = std::make_shared<RuleEngine>();
    Rule r1;
    r1.id = 1;
    r1.name = "Block Telnet";
    r1.priority = 10;
    r1.action = RuleAction::Block;
    r1.dst_port_range = "23";
    rule_engine->add_rule(r1);

    Rule r2;
    r2.id = 2;
    r2.name = "Block Ad Domain";
    r2.priority = 20;
    r2.action = RuleAction::Block;
    r2.domain_pattern = "*.doubleclick.net";
    rule_engine->add_rule(r2);

    std::vector<std::vector<uint8_t>> pcap_pkts;

    // Flow 1: Telnet (Blocked at L3/L4)
    pcap_pkts.push_back(make_ipv4_tcp_packet(0x0A000001, 10001, 0x0A000002, 23, 100, 0, 0x02));

    // Flow 2: HTTP to allowed host
    std::string http_allowed = "GET /index.html HTTP/1.1\r\nHost: github.com\r\n\r\n";
    pcap_pkts.push_back(make_ipv4_tcp_packet(0x0A000001, 10002, 0x0A000003, 80, 200, 0, 0x18, http_allowed));

    // Flow 3: HTTP to blocked domain
    std::string http_blocked = "GET /ad.js HTTP/1.1\r\nHost: ad.doubleclick.net\r\n\r\n";
    pcap_pkts.push_back(make_ipv4_tcp_packet(0x0A000001, 10003, 0x0A000004, 80, 300, 0, 0x18, http_blocked));

    std::string pcap_str = make_synthetic_pcap_stream(pcap_pkts);
    std::stringstream ss(pcap_str);
    PcapReader reader;
    assert(reader.open(ss) == PcapErrorCode::Success);

    WorkerConfig config;
    config.num_workers = 3;
    WorkerPool pool(config, rule_engine);

    PipelineStats stats = pool.process_pcap(reader);
    assert(stats.total_packets == 3);
    assert(stats.total_flows == 3);
    assert(stats.total_blocked_packets == 2); // Telnet + doubleclick.net
    assert(stats.total_dpi_classified_flows == 2); // 2 HTTP flows classified
}

int main() {
    std::cout << "========================================\n";
    std::cout << "  Stage 6 Multi-Worker Pipeline Tests   \n";
    std::cout << "========================================\n";

    test_bounded_queue_basic_and_backpressure();
    test_flow_router_minimal_parse();
    test_deterministic_flow_affinity_bidirectional();
    test_concurrent_independent_flows();
    test_in_order_packet_processing_per_flow();
    test_graceful_shutdown_and_drain();
    test_edge_cases_empty_pcap_and_malformed();
    test_end_to_end_pcap_pipeline_with_rules_and_dpi();

    std::cout << "All Stage 6 Multi-Worker Pipeline tests PASSED!\n";
    return 0;
}
