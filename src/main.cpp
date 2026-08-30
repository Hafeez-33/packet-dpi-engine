#include "dpi/packet/pcap_reader.h"
#include "dpi/pipeline/worker_pool.h"
#include "dpi/rules/rule_engine.h"
#include "dpi/rules/rule_parser.h"
#include "dpi/telemetry/telemetry_collector.h"
#include "dpi/version.h"
#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

using namespace dpi;

static void print_usage(const char* prog_name) {
    std::cout << "Usage: " << prog_name << " [options]\n\n"
              << "Options:\n"
              << "  --pcap <file>            Path to input PCAP file for processing\n"
              << "  --workers <count>        Number of fast-path worker threads (default: hardware concurrency)\n"
              << "  --rules <file>           Path to JSON rule configuration file\n"
              << "  --telemetry-file <file>  Path to output telemetry snapshot JSON (default: telemetry_snapshot.json)\n"
              << "  --max-flows <count>      Maximum flow records retained in telemetry snapshot (default: 1000)\n"
              << "  -h, --help               Display this help message and exit\n"
              << "  -v, --version            Display version information and exit\n";
}

int main(int argc, char* argv[]) {
    std::string pcap_path{};
    std::string rules_path{};
    std::string telemetry_path = "telemetry_snapshot.json";
    size_t num_workers = 0;
    size_t max_flows = 1000;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "-v" || arg == "--version") {
            std::cout << "Packet DPI Engine v" << get_version_string() << "\n";
            return 0;
        } else if (arg == "--pcap" && i + 1 < argc) {
            pcap_path = argv[++i];
        } else if (arg == "--workers" && i + 1 < argc) {
            num_workers = static_cast<size_t>(std::strtoul(argv[++i], nullptr, 10));
        } else if (arg == "--rules" && i + 1 < argc) {
            rules_path = argv[++i];
        } else if (arg == "--telemetry-file" && i + 1 < argc) {
            telemetry_path = argv[++i];
        } else if (arg == "--max-flows" && i + 1 < argc) {
            max_flows = static_cast<size_t>(std::strtoul(argv[++i], nullptr, 10));
        } else {
            std::cerr << "Unknown or incomplete option: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    std::cout << "=======================================================\n";
    std::cout << "  Packet DPI Engine v" << get_version_string() << " (Stage 7 Production Core)\n";
    std::cout << "=======================================================\n";

    // 1. Initialize Rule Engine
    auto rule_engine = std::make_shared<RuleEngine>();
    if (!rules_path.empty()) {
        std::cout << "[CONFIG] Loading policy rules from: " << rules_path << "\n";
        auto load_res = rule_engine->load_rules_from_file(rules_path);
        if (!load_res.success) {
            std::cerr << "[ERROR] Failed to load rules: " << load_res.error_message << "\n";
            return 1;
        }
        std::cout << "[CONFIG] Successfully loaded " << rule_engine->rule_count()
                  << " security policy rules.\n";
    }

    // 2. Configure Worker Pool
    WorkerConfig config{};
    config.num_workers = num_workers;
    config.queue_capacity = 4096;

    WorkerPool pool(config, rule_engine);
    TelemetryCollector collector(pool, max_flows);
    collector.set_status(EngineStatus::Running);

    std::cout << "[PIPELINE] Initialized multi-worker pipeline with " << pool.worker_count()
              << " worker threads.\n";
    std::cout << "[TELEMETRY] Live telemetry output file: " << telemetry_path << "\n";

    if (pcap_path.empty()) {
        std::cout << "[INFO] No --pcap input specified. Exporting initial idle telemetry snapshot.\n";
        collector.set_status(EngineStatus::Completed);
        collector.export_json_atomic(telemetry_path);
        std::cout << "[INFO] Telemetry written. Run with --pcap <capture.pcap> to process network traffic.\n";
        return 0;
    }

    // 3. Open PCAP file
    PcapReader reader;
    PcapErrorCode err = reader.open(pcap_path);
    if (err != PcapErrorCode::Success) {
        std::cerr << "[ERROR] Failed to open PCAP file '" << pcap_path
                  << "': " << pcap_error_to_string(err) << "\n";
        collector.set_status(EngineStatus::Error);
        collector.export_json_atomic(telemetry_path);
        return 1;
    }

    std::cout << "[INGEST] Ingesting packets from: " << pcap_path << " ...\n";
    auto start_time = std::chrono::high_resolution_clock::now();

    pool.start();

    // 4. Ingestion loop with periodic telemetry sync
    PacketRecord record;
    bool is_nanoseconds = reader.global_header().is_nanosecond_resolution;
    auto last_telemetry_sync = std::chrono::steady_clock::now();

    while (reader.read_next_packet(record) == PcapErrorCode::Success) {
        pool.dispatch(std::move(record), is_nanoseconds);

        // Periodic telemetry snapshot export every 500ms
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_telemetry_sync).count() >= 500) {
            collector.export_json_atomic(telemetry_path);
            last_telemetry_sync = now;
        }
    }

    // 5. Drain and terminate
    pool.stop();
    auto end_time = std::chrono::high_resolution_clock::now();
    double total_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();

    // 6. Export final completed telemetry snapshot
    collector.set_status(EngineStatus::Completed);
    collector.export_json_atomic(telemetry_path);

    TelemetrySnapshot final_snap = collector.capture_snapshot();

    std::cout << "\n=======================================================\n";
    std::cout << "                 EXECUTION SUMMARY                     \n";
    std::cout << "=======================================================\n";
    std::cout << "Status:               COMPLETED\n";
    std::cout << "Total Packets:        " << final_snap.total_packets << "\n";
    std::cout << "Total Bytes:          " << final_snap.total_bytes << " ("
              << std::fixed << std::setprecision(2) << (final_snap.total_bytes / (1024.0 * 1024.0)) << " MB)\n";
    std::cout << "Total Flows:          " << final_snap.total_flows << "\n";
    std::cout << "Processing Time:      " << std::fixed << std::setprecision(2) << total_ms << " ms\n";
    if (total_ms > 0) {
        double kpps = (final_snap.total_packets / total_ms);
        double mbps = (final_snap.total_bytes / (1024.0 * 1024.0)) / (total_ms / 1000.0);
        std::cout << "Throughput:           " << std::fixed << std::setprecision(2) << kpps << " kpkts/s ("
                  << mbps << " MB/s)\n";
    }
    std::cout << "Blocked Traffic:      " << final_snap.blocked_packets << " packets ("
              << final_snap.blocked_flows << " flows)\n";
    std::cout << "DPI Classified:       TLS=" << final_snap.tls_flows
              << ", HTTP=" << final_snap.http_flows
              << ", DNS=" << final_snap.dns_flows
              << ", Unknown=" << final_snap.unknown_l7_flows << "\n";
    std::cout << "Final Telemetry:      " << telemetry_path << "\n";
    std::cout << "=======================================================\n";

    return 0;
}
