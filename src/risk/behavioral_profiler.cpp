#include "dpi/risk/behavioral_profiler.h"
#include <cmath>
#include <algorithm>

namespace dpi {

void FlowBehavioralProfiler::update_metrics(BehavioralMetrics& metrics,
                                           const ParsedPacket& packet,
                                           uint64_t timestamp_us,
                                           bool is_forward) noexcept {
    // 1. Packet & Byte counters
    size_t payload_len = packet.l7_payload.size();
    if (is_forward) {
        metrics.fwd_packets++;
        metrics.fwd_bytes += payload_len;
    } else {
        metrics.rev_packets++;
        metrics.rev_bytes += payload_len;
    }

    // 2. Packet size histogram
    if (payload_len < 128) {
        metrics.small_packets++;
    } else if (payload_len <= 1024) {
        metrics.medium_packets++;
    } else {
        metrics.large_packets++;
    }

    // 3. Directional byte ratio calculation
    uint64_t denom = std::max<uint64_t>(1, metrics.rev_bytes);
    metrics.byte_ratio = static_cast<double>(metrics.fwd_bytes) / static_cast<double>(denom);

    // 4. Inter-arrival time (IAT) calculation using Welford's online algorithm
    if (metrics.last_packet_ts_us > 0 && timestamp_us >= metrics.last_packet_ts_us) {
        uint64_t delta_us = timestamp_us - metrics.last_packet_ts_us;
        double delta_ms = static_cast<double>(delta_us) / 1000.0;

        metrics.iat_count++;
        double count_d = static_cast<double>(metrics.iat_count);

        if (metrics.iat_count == 1) {
            metrics.mean_iat_ms = delta_ms;
            metrics.m2_iat_ms2 = 0.0;
            metrics.iat_variance_ms2 = 0.0;
            metrics.iat_stddev_ms = 0.0;
            metrics.iat_jitter_ratio = 0.0;
        } else {
            double delta = delta_ms - metrics.mean_iat_ms;
            metrics.mean_iat_ms += delta / count_d;
            double delta2 = delta_ms - metrics.mean_iat_ms;
            metrics.m2_iat_ms2 += delta * delta2;

            metrics.iat_variance_ms2 = metrics.m2_iat_ms2 / (count_d - 1.0);
            metrics.iat_stddev_ms = std::sqrt(std::max(0.0, metrics.iat_variance_ms2));

            if (metrics.mean_iat_ms > 0.0001) {
                metrics.iat_jitter_ratio = metrics.iat_stddev_ms / metrics.mean_iat_ms;
            } else {
                metrics.iat_jitter_ratio = 0.0;
            }
        }
    }

    metrics.last_packet_ts_us = timestamp_us;
}

} // namespace dpi
