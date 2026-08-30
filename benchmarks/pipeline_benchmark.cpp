#include "dpi/dpi/dpi_engine.h"
#include "dpi/flow/flow_table.h"
#include "dpi/packet/pcap_reader.h"
#include "dpi/pipeline/worker_pool.h"
#include "dpi/protocols/protocol_parser.h"
#include "dpi/rules/rule_engine.h"
#include <chrono>
#include <iomanip>
#include <iostream>
#include <sstream>
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

// Generate in-memory PCAP stream
static std::string generate_synthetic_pcap(size_t num_packets, size_t num_flows) {
    std::stringstream ss(std::ios::in | std::ios::out | std::ios::binary);

    auto write_u32_le = [](std::ostream& os, uint32_t val) {
        os.write(reinterpret_cast<const char*>(&val), sizeof(val));
    };
    auto write_u16_le = [](std::ostream& os, uint16_t val) {
        os.write(reinterpret_cast<const char*>(&val), sizeof(val));
    };

    write_u32_le(ss, pcap_magic::MICROSEC_NATIVE);
    write_u16_le(ss, 2);
    write_u16_le(ss, 4);
    write_u32_le(ss, 0);
    write_u32_le(ss, 0);
    write_u32_le(ss, 65535);
    write_u32_le(ss, 1);

    std::string http_payload = "GET /index.html HTTP/1.1\r\nHost: benchmark.org\r\n\r\n";

    for (size_t i = 0; i < num_packets; ++i) {
        uint32_t flow_id = static_cast<uint32_t>(i % num_flows);
        uint32_t src_ip = 0x0A000000 + (flow_id % 250);
        uint32_t dst_ip = 0x0A010000 + (flow_id / 250);
        uint16_t src_port = static_cast<uint16_t>(10000 + (flow_id % 5000));
        uint16_t dst_port = 80;

        std::vector<uint8_t> pkt;
        append_ethernet(pkt, ethertype::IPV4);
        append_ipv4(pkt, static_cast<uint16_t>(40 + http_payload.size()), ipproto::TCP, src_ip, dst_ip);
        append_tcp(pkt, src_port, dst_port, static_cast<uint32_t>(i * 100), 100, 0x18);
        pkt.insert(pkt.end(), http_payload.begin(), http_payload.end());

        write_u32_le(ss, 1600000000 + static_cast<uint32_t>(i / 1000));
        write_u32_le(ss, static_cast<uint32_t>((i % 1000) * 1000));
        write_u32_le(ss, static_cast<uint32_t>(pkt.size()));
        write_u32_le(ss, static_cast<uint32_t>(pkt.size()));
        ss.write(reinterpret_cast<const char*>(pkt.data()), pkt.size());
    }

    return ss.str();
}

int main() {
    std::cout << "========================================================================\n";
    std::cout << "        Packet DPI Engine - Multi-Worker Pipeline Benchmark             \n";
    std::cout << "========================================================================\n\n";

    constexpr size_t NUM_PACKETS = 50000;
    constexpr size_t NUM_FLOWS = 500;

    std::cout << "Generating " << NUM_PACKETS << " packets across " << NUM_FLOWS << " flows...\n";
    std::string pcap_data = generate_synthetic_pcap(NUM_PACKETS, NUM_FLOWS);
    size_t total_mb = pcap_data.size() / (1024 * 1024);
    std::cout << "Synthetic PCAP generated: " << total_mb << " MB (" << pcap_data.size() << " bytes)\n\n";

    auto rule_engine = std::make_shared<RuleEngine>();
    Rule r;
    r.id = 1;
    r.name = "Benchmark Block Rule";
    r.priority = 10;
    r.action = RuleAction::Block;
    r.domain_pattern = "blocked-benchmark.org";
    rule_engine->add_rule(r);

    // 1. Sequential Processing Baseline
    {
        std::stringstream ss(pcap_data);
        PcapReader reader;
        reader.open(ss);

        FlowTable table;
        table.set_rule_engine(rule_engine);

        auto start = std::chrono::high_resolution_clock::now();
        PacketRecord rec;
        size_t pkts = 0;
        size_t bytes = 0;
        while (reader.read_next_packet(rec) == PcapErrorCode::Success) {
            ParsedPacket parsed = ProtocolParser::parse(rec);
            table.process_packet(rec, parsed, false);
            pkts++;
            bytes += rec.payload.size();
        }
        auto end = std::chrono::high_resolution_clock::now();
        double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
        double mpps = (pkts / elapsed_ms) / 1000.0;
        double mbps = (bytes / (1024.0 * 1024.0)) / (elapsed_ms / 1000.0);

        std::cout << std::left << std::setw(22) << "Sequential Baseline:"
                  << std::right << std::setw(8) << std::fixed << std::setprecision(2) << elapsed_ms << " ms | "
                  << std::setw(8) << std::setprecision(2) << (mpps * 1000.0) << " kpkts/s | "
                  << std::setw(8) << std::setprecision(2) << mbps << " MB/s | "
                  << "Flows: " << table.size() << "\n";
    }

    // 2. Multi-Worker Pipelines
    std::vector<size_t> worker_counts = {1, 2, 4, 8};
    for (size_t num_w : worker_counts) {
        std::stringstream ss(pcap_data);
        PcapReader reader;
        reader.open(ss);

        WorkerConfig cfg;
        cfg.num_workers = num_w;
        cfg.queue_capacity = 4096;

        WorkerPool pool(cfg, rule_engine);

        auto start = std::chrono::high_resolution_clock::now();
        PipelineStats stats = pool.process_pcap(reader);
        auto end = std::chrono::high_resolution_clock::now();

        double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
        double mpps = (stats.total_packets / elapsed_ms) / 1000.0;
        double mbps = (stats.total_bytes / (1024.0 * 1024.0)) / (elapsed_ms / 1000.0);

        std::string label = "WorkerPool (" + std::to_string(num_w) + " workers):";
        std::cout << std::left << std::setw(22) << label
                  << std::right << std::setw(8) << std::fixed << std::setprecision(2) << elapsed_ms << " ms | "
                  << std::setw(8) << std::setprecision(2) << (mpps * 1000.0) << " kpkts/s | "
                  << std::setw(8) << std::setprecision(2) << mbps << " MB/s | "
                  << "Flows: " << stats.total_flows << "\n";
    }

    std::cout << "\nBenchmark completed successfully.\n";
    return 0;
}
