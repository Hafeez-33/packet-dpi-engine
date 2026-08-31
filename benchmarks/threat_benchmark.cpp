#include "dpi/threat/entropy_calculator.h"
#include "dpi/threat/threat_engine.h"
#include "dpi/pipeline/worker_pool.h"
#include "dpi/packet/pcap_reader.h"
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <vector>

using namespace dpi;

static std::string create_benchmark_pcap_file(size_t num_packets) {
    std::string filename = "bench_threat_traffic.pcap";
    std::ofstream ofs(filename, std::ios::binary);

    // Global header
    uint32_t magic = 0xa1b2c3d4;
    uint16_t v_maj = 2, v_min = 4;
    int32_t thiszone = 0;
    uint32_t sigfigs = 0, snaplen = 65535, network = 1;

    ofs.write(reinterpret_cast<const char*>(&magic), 4);
    ofs.write(reinterpret_cast<const char*>(&v_maj), 2);
    ofs.write(reinterpret_cast<const char*>(&v_min), 2);
    ofs.write(reinterpret_cast<const char*>(&thiszone), 4);
    ofs.write(reinterpret_cast<const char*>(&sigfigs), 4);
    ofs.write(reinterpret_cast<const char*>(&snaplen), 4);
    ofs.write(reinterpret_cast<const char*>(&network), 4);

    // Build payload containing HTTP GET with SQLi and domain
    std::string http_payload = "GET /search?q=test%20UNION%20SELECT%201,2,3 HTTP/1.1\r\nHost: anomaly-dga-9f8e7d6c5b4a.evil.org\r\nUser-Agent: sqlmap/1.6\r\n\r\n";

    std::vector<uint8_t> pkt;
    // Ethernet (14 bytes)
    for (int i = 0; i < 12; ++i) pkt.push_back(0);
    pkt.push_back(0x08); pkt.push_back(0x00);
    // IPv4 (20 bytes)
    pkt.push_back(0x45); pkt.push_back(0x00);
    uint16_t tot = 20 + 20 + static_cast<uint16_t>(http_payload.size());
    pkt.push_back(tot >> 8); pkt.push_back(tot & 0xFF);
    pkt.push_back(0x12); pkt.push_back(0x34);
    pkt.push_back(0x40); pkt.push_back(0x00);
    pkt.push_back(64); pkt.push_back(6);
    pkt.push_back(0); pkt.push_back(0);
    // 192.168.1.100 -> 10.0.0.1
    pkt.push_back(192); pkt.push_back(168); pkt.push_back(1); pkt.push_back(100);
    pkt.push_back(10); pkt.push_back(0); pkt.push_back(0); pkt.push_back(1);
    // TCP (20 bytes)
    pkt.push_back(0x1F); pkt.push_back(0x90); // 8080
    pkt.push_back(0x00); pkt.push_back(0x50); // 80
    pkt.push_back(0); pkt.push_back(0); pkt.push_back(0); pkt.push_back(1);
    pkt.push_back(0); pkt.push_back(0); pkt.push_back(0); pkt.push_back(1);
    pkt.push_back(0x50); pkt.push_back(0x18); // PSH, ACK
    pkt.push_back(0x10); pkt.push_back(0x00);
    pkt.push_back(0); pkt.push_back(0);
    pkt.push_back(0); pkt.push_back(0);
    pkt.insert(pkt.end(), http_payload.begin(), http_payload.end());

    for (size_t i = 0; i < num_packets; ++i) {
        uint32_t ts_sec = static_cast<uint32_t>(i / 1000);
        uint32_t ts_usec = static_cast<uint32_t>((i % 1000) * 1000);
        uint32_t caplen = static_cast<uint32_t>(pkt.size());
        uint32_t origlen = static_cast<uint32_t>(pkt.size());

        ofs.write(reinterpret_cast<const char*>(&ts_sec), 4);
        ofs.write(reinterpret_cast<const char*>(&ts_usec), 4);
        ofs.write(reinterpret_cast<const char*>(&caplen), 4);
        ofs.write(reinterpret_cast<const char*>(&origlen), 4);
        ofs.write(reinterpret_cast<const char*>(pkt.data()), pkt.size());
    }

    ofs.close();
    return filename;
}

int main() {
    std::cout << "===========================================================\n";
    std::cout << "  Stage 8: Threat Detection & IDS Benchmark Suite          \n";
    std::cout << "===========================================================\n";

    // Benchmark 1: Raw Shannon Entropy Calculation Throughput
    const size_t ENTROPY_ITERS = 1000000;
    std::string sample_domain = "subdomain-exfiltration-payload-9f8e7d6c5b4a.badactor.org";

    auto t0 = std::chrono::high_resolution_clock::now();
    double sum_entropy = 0.0;
    for (size_t i = 0; i < ENTROPY_ITERS; ++i) {
        sum_entropy += EntropyCalculator::calculate_shannon_entropy(sample_domain);
    }
    auto t1 = std::chrono::high_resolution_clock::now();
    double entropy_elapsed_s = std::chrono::duration<double>(t1 - t0).count();
    double entropy_mops = (static_cast<double>(ENTROPY_ITERS) / entropy_elapsed_s) / 1e6;

    std::cout << "\n[1] Shannon Entropy Microbenchmark:\n";
    std::cout << "    Iterations:          " << ENTROPY_ITERS << "\n";
    std::cout << "    Time Elapsed:        " << std::fixed << std::setprecision(3) << (entropy_elapsed_s * 1000.0) << " ms\n";
    std::cout << "    Calculation Rate:    " << std::fixed << std::setprecision(2) << entropy_mops << " Million ops/sec\n";
    std::cout << "    Sample Entropy:      " << (sum_entropy / static_cast<double>(ENTROPY_ITERS)) << " bits/char\n";

    // Benchmark 2: End-to-end Pipeline with vs without Threat Engine
    const size_t BENCH_PACKETS = 50000;
    std::string pcap_file = create_benchmark_pcap_file(BENCH_PACKETS);

    // Run A: Pipeline with Threat Detection DISABLED
    WorkerConfig cfg_disabled;
    cfg_disabled.num_workers = 4;
    cfg_disabled.threat_config.enabled = false;
    WorkerPool pool_disabled(cfg_disabled);

    PcapReader reader_a;
    reader_a.open(pcap_file);

    auto start_a = std::chrono::high_resolution_clock::now();
    PipelineStats stats_a = pool_disabled.process_pcap(reader_a);
    auto end_a = std::chrono::high_resolution_clock::now();
    double sec_a = std::chrono::duration<double>(end_a - start_a).count();
    double kpps_a = (stats_a.total_packets / sec_a) / 1000.0;

    // Run B: Pipeline with Stage 8 Threat Detection ENABLED
    WorkerConfig cfg_enabled;
    cfg_enabled.num_workers = 4;
    cfg_enabled.threat_config.enabled = true;
    WorkerPool pool_enabled(cfg_enabled);

    PcapReader reader_b;
    reader_b.open(pcap_file);

    auto start_b = std::chrono::high_resolution_clock::now();
    PipelineStats stats_b = pool_enabled.process_pcap(reader_b);
    auto end_b = std::chrono::high_resolution_clock::now();
    double sec_b = std::chrono::duration<double>(end_b - start_b).count();
    double kpps_b = (stats_b.total_packets / sec_b) / 1000.0;

    double overhead_pct = ((kpps_a - kpps_b) / kpps_a) * 100.0;

    std::cout << "\n[2] End-to-End Multi-Worker Pipeline Throughput Comparison:\n";
    std::cout << "    Workload:            " << BENCH_PACKETS << " HTTP packets with attack patterns\n";
    std::cout << "    Worker Threads:      4\n";
    std::cout << "    -------------------------------------------------------\n";
    std::cout << "    A. Threat Engine OFF: " << std::fixed << std::setprecision(2) << kpps_a << " kpkts/s (" << (sec_a * 1000.0) << " ms)\n";
    std::cout << "    B. Threat Engine ON:  " << std::fixed << std::setprecision(2) << kpps_b << " kpkts/s (" << (sec_b * 1000.0) << " ms)\n";
    std::cout << "       Alerts Generated:  " << stats_b.total_threat_alerts_generated << " security alerts\n";
    std::cout << "       Alerts Dropped:    " << stats_b.total_threat_alerts_dropped << "\n";
    std::cout << "    -------------------------------------------------------\n";
    std::cout << "    Measured Overhead:   " << std::fixed << std::setprecision(2) << overhead_pct << " %\n";
    std::cout << "===========================================================\n";

    return 0;
}
