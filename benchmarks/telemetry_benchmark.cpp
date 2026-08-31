#include "dpi/packet/pcap_reader.h"
#include "dpi/pipeline/worker_pool.h"
#include "dpi/rules/rule_engine.h"
#include "dpi/telemetry/telemetry_collector.h"
#include <chrono>
#include <filesystem>
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
        for (int b = 0; b < 12; ++b) pkt.push_back(0);
        push_u16_be(pkt, ethertype::IPV4);

        pkt.push_back(0x45);
        pkt.push_back(0x00);
        push_u16_be(pkt, static_cast<uint16_t>(40 + http_payload.size()));
        push_u16_be(pkt, 0x1234);
        push_u16_be(pkt, 0x4000);
        pkt.push_back(64);
        pkt.push_back(ipproto::TCP);
        push_u16_be(pkt, 0);
        push_u32_be(pkt, src_ip);
        push_u32_be(pkt, dst_ip);

        push_u16_be(pkt, src_port);
        push_u16_be(pkt, dst_port);
        push_u32_be(pkt, static_cast<uint32_t>(i * 100));
        push_u32_be(pkt, 100);
        push_u16_be(pkt, (5u << 12) | 0x18);
        push_u16_be(pkt, 65535);
        push_u16_be(pkt, 0);
        push_u16_be(pkt, 0);

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
    std::cout << "        Stage 7 Telemetry Overhead Benchmark Comparison                 \n";
    std::cout << "========================================================================\n\n";

    constexpr size_t NUM_PACKETS = 50000;
    constexpr size_t NUM_FLOWS = 500;
    std::string pcap_data = generate_synthetic_pcap(NUM_PACKETS, NUM_FLOWS);

    auto rule_engine = std::make_shared<RuleEngine>();
    Rule r;
    r.id = 1;
    r.name = "Block Benchmark";
    r.priority = 10;
    r.action = RuleAction::Block;
    r.domain_pattern = "blocked-benchmark.org";
    rule_engine->add_rule(r);

    WorkerConfig config;
    config.num_workers = 4;
    config.queue_capacity = 4096;

    // 1. Stage 6 Pipeline WITHOUT Telemetry
    double time_without_ms = 0.0;
    double mpps_without = 0.0;
    double mbps_without = 0.0;
    {
        std::stringstream ss(pcap_data);
        PcapReader reader;
        reader.open(ss);

        WorkerPool pool(config, rule_engine);

        auto start = std::chrono::high_resolution_clock::now();
        PipelineStats stats = pool.process_pcap(reader);
        auto end = std::chrono::high_resolution_clock::now();

        time_without_ms = std::chrono::duration<double, std::milli>(end - start).count();
        mpps_without = (stats.total_packets / time_without_ms) / 1000.0;
        mbps_without = (stats.total_bytes / (1024.0 * 1024.0)) / (time_without_ms / 1000.0);

        std::cout << std::left << std::setw(32) << "Pipeline WITHOUT Telemetry:"
                  << std::right << std::setw(8) << std::fixed << std::setprecision(2) << time_without_ms << " ms | "
                  << std::setw(8) << std::setprecision(2) << (mpps_without * 1000.0) << " kpkts/s | "
                  << std::setw(8) << std::setprecision(2) << mbps_without << " MB/s\n";
    }

    // 2. Stage 7 Pipeline WITH Periodic Telemetry & Atomic JSON Export
    double time_with_ms = 0.0;
    double mpps_with = 0.0;
    double mbps_with = 0.0;
    std::string test_telemetry_file = "benchmark_telemetry.json";
    {
        std::stringstream ss(pcap_data);
        PcapReader reader;
        reader.open(ss);

        WorkerPool pool(config, rule_engine);
        TelemetryCollector collector(pool, 500);
        collector.set_status(EngineStatus::Running);

        auto start = std::chrono::high_resolution_clock::now();
        pool.start();

        PacketRecord record;
        bool is_nanoseconds = reader.global_header().is_nanosecond_resolution;
        auto last_sync = std::chrono::steady_clock::now();

        while (reader.read_next_packet(record) == PcapErrorCode::Success) {
            pool.dispatch(std::move(record), is_nanoseconds);

            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_sync).count() >= 50) {
                collector.export_json_atomic(test_telemetry_file, false);
                last_sync = now;
            }
        }

        pool.stop();
        collector.set_status(EngineStatus::Completed);
        collector.export_json_atomic(test_telemetry_file, true);

        auto end = std::chrono::high_resolution_clock::now();
        time_with_ms = std::chrono::duration<double, std::milli>(end - start).count();
        PipelineStats stats = pool.get_aggregated_stats();
        mpps_with = (stats.total_packets / time_with_ms) / 1000.0;
        mbps_with = (stats.total_bytes / (1024.0 * 1024.0)) / (time_with_ms / 1000.0);

        std::cout << std::left << std::setw(32) << "Pipeline WITH Telemetry (JSON Sync):"
                  << std::right << std::setw(8) << std::fixed << std::setprecision(2) << time_with_ms << " ms | "
                  << std::setw(8) << std::setprecision(2) << (mpps_with * 1000.0) << " kpkts/s | "
                  << std::setw(8) << std::setprecision(2) << mbps_with << " MB/s\n";
    }

    std::filesystem::remove(test_telemetry_file);
    std::filesystem::remove(test_telemetry_file + ".tmp");

    double overhead_pct = ((time_with_ms - time_without_ms) / time_without_ms) * 100.0;
    std::cout << "\nMeasured Telemetry CPU/Runtime Overhead: "
              << std::fixed << std::setprecision(2) << overhead_pct << "%\n";

    return 0;
}
