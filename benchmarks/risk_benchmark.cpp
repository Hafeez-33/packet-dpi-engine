#include "dpi/risk/behavioral_profiler.h"
#include "dpi/pipeline/worker_pool.h"
#include "dpi/packet/pcap_reader.h"
#include <chrono>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using namespace dpi;

static void create_benchmark_pcap(const std::string& filename, size_t packet_count) {
    std::ofstream ofs(filename, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open()) return;

    // Classic PCAP Global Header (24 bytes)
    uint32_t magic = 0xa1b2c3d4;
    uint16_t v_major = 2, v_minor = 4;
    int32_t thiszone = 0;
    uint32_t sigfigs = 0, snaplen = 65535, network = 1;

    ofs.write(reinterpret_cast<const char*>(&magic), 4);
    ofs.write(reinterpret_cast<const char*>(&v_major), 2);
    ofs.write(reinterpret_cast<const char*>(&v_minor), 2);
    ofs.write(reinterpret_cast<const char*>(&thiszone), 4);
    ofs.write(reinterpret_cast<const char*>(&sigfigs), 4);
    ofs.write(reinterpret_cast<const char*>(&snaplen), 4);
    ofs.write(reinterpret_cast<const char*>(&network), 4);

    std::string payload = "GET /status HTTP/1.1\r\nHost: api.internal.corp\r\nUser-Agent: Agent/1.0\r\n\r\n";

    for (size_t i = 0; i < packet_count; ++i) {
        std::vector<uint8_t> pkt;
        // Ethernet (14)
        for (int k = 0; k < 12; ++k) pkt.push_back(0x00);
        pkt.push_back(0x08); pkt.push_back(0x00);

        // IPv4 (20)
        pkt.push_back(0x45); pkt.push_back(0x00);
        uint16_t tot = 40 + static_cast<uint16_t>(payload.size());
        pkt.push_back(static_cast<uint8_t>(tot >> 8)); pkt.push_back(static_cast<uint8_t>(tot & 0xFF));
        pkt.push_back(0x12); pkt.push_back(0x34);
        pkt.push_back(0x40); pkt.push_back(0x00);
        pkt.push_back(64); pkt.push_back(6);
        pkt.push_back(0x00); pkt.push_back(0x00);
        // src 192.168.1.(i % 250 + 1), dst 10.0.0.1
        pkt.push_back(192); pkt.push_back(168); pkt.push_back(1); pkt.push_back(static_cast<uint8_t>((i % 250) + 1));
        pkt.push_back(10); pkt.push_back(0); pkt.push_back(0); pkt.push_back(1);

        // TCP (20)
        uint16_t sport = static_cast<uint16_t>(10000 + (i % 1000));
        pkt.push_back(static_cast<uint8_t>(sport >> 8)); pkt.push_back(static_cast<uint8_t>(sport & 0xFF));
        pkt.push_back(0x00); pkt.push_back(80);
        pkt.push_back(0x00); pkt.push_back(0x00); pkt.push_back(0x00); pkt.push_back(0x01);
        pkt.push_back(0x00); pkt.push_back(0x00); pkt.push_back(0x00); pkt.push_back(0x02);
        pkt.push_back(0x50); pkt.push_back(0x18);
        pkt.push_back(0x10); pkt.push_back(0x00);
        pkt.push_back(0x00); pkt.push_back(0x00);
        pkt.push_back(0x00); pkt.push_back(0x00);

        pkt.insert(pkt.end(), payload.begin(), payload.end());

        uint32_t ts_sec = static_cast<uint32_t>(1000 + (i / 1000));
        uint32_t ts_usec = static_cast<uint32_t>((i % 1000) * 1000);
        uint32_t caplen = static_cast<uint32_t>(pkt.size());
        uint32_t origlen = caplen;

        ofs.write(reinterpret_cast<const char*>(&ts_sec), 4);
        ofs.write(reinterpret_cast<const char*>(&ts_usec), 4);
        ofs.write(reinterpret_cast<const char*>(&caplen), 4);
        ofs.write(reinterpret_cast<const char*>(&origlen), 4);
        ofs.write(reinterpret_cast<const char*>(pkt.data()), pkt.size());
    }
}

int main() {
    std::cout << "===========================================================\n";
    std::cout << "  Stage 9: Risk & Behavioral Profiling Benchmark Suite     \n";
    std::cout << "===========================================================\n\n";

    // 1. Welford Profiling Microbenchmark
    {
        std::cout << "[1] Welford IAT Calculation Microbenchmark:\n";
        BehavioralMetrics metrics{};
        ParsedPacket dummy_pkt{};
        dummy_pkt.l7_payload = "GET /test HTTP/1.1";

        constexpr size_t ITERATIONS = 1000000;
        auto start = std::chrono::high_resolution_clock::now();

        for (size_t i = 0; i < ITERATIONS; ++i) {
            FlowBehavioralProfiler::update_metrics(metrics, dummy_pkt, 1000000 + i * 500, true);
        }

        auto end = std::chrono::high_resolution_clock::now();
        double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
        double mops = (static_cast<double>(ITERATIONS) / (elapsed_ms / 1000.0)) / 1000000.0;

        std::cout << "    Iterations:          " << ITERATIONS << "\n";
        std::cout << "    Time Elapsed:        " << elapsed_ms << " ms\n";
        std::cout << "    Calculation Rate:    " << mops << " Million ops/sec\n\n";
    }

    // 2. Multi-Worker Pipeline Throughput with vs without Risk Engine
    std::string pcap_file = "bench_risk_traffic.pcap";
    create_benchmark_pcap(pcap_file, 50000);

    // Run A: Pipeline with Risk Engine DISABLED
    WorkerConfig cfg_disabled;
    cfg_disabled.num_workers = 4;
    cfg_disabled.risk_config.enabled = false;
    WorkerPool pool_disabled(cfg_disabled);

    PcapReader reader_a;
    reader_a.open(pcap_file);

    auto start_a = std::chrono::high_resolution_clock::now();
    PipelineStats stats_a = pool_disabled.process_pcap(reader_a);
    auto end_a = std::chrono::high_resolution_clock::now();
    double sec_a = std::chrono::duration<double>(end_a - start_a).count();
    double kpps_a = (stats_a.total_packets / sec_a) / 1000.0;

    // Run B: Pipeline with Risk Engine ENABLED
    WorkerConfig cfg_enabled;
    cfg_enabled.num_workers = 4;
    cfg_enabled.risk_config.enabled = true;
    WorkerPool pool_enabled(cfg_enabled);

    PcapReader reader_b;
    reader_b.open(pcap_file);

    auto start_b = std::chrono::high_resolution_clock::now();
    PipelineStats stats_b = pool_enabled.process_pcap(reader_b);
    auto end_b = std::chrono::high_resolution_clock::now();
    double sec_b = std::chrono::duration<double>(end_b - start_b).count();
    double kpps_b = (stats_b.total_packets / sec_b) / 1000.0;

    std::cout << "[2] End-to-End Multi-Worker Pipeline Throughput Comparison:\n";
    std::cout << "    Workload:            50000 packets\n";
    std::cout << "    Worker Threads:      4\n";
    std::cout << "    -------------------------------------------------------\n";
    std::cout << "    A. Risk Engine OFF:  " << kpps_a << " kpkts/s (" << (sec_a * 1000.0) << " ms)\n";
    std::cout << "    B. Risk Engine ON:   " << kpps_b << " kpkts/s (" << (sec_b * 1000.0) << " ms)\n";
    std::cout << "    -------------------------------------------------------\n";
    double overhead_pct = ((sec_b - sec_a) / sec_a) * 100.0;
    std::cout << "    Measured Overhead:   " << (overhead_pct < 0 ? 0.0 : overhead_pct) << " %\n";
    std::cout << "===========================================================\n";

    return 0;
}
