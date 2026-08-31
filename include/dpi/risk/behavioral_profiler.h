#ifndef DPI_BEHAVIORAL_PROFILER_H
#define DPI_BEHAVIORAL_PROFILER_H

#include "dpi/risk/risk_types.h"
#include "dpi/protocols/parsed_packet.h"
#include <cstdint>

namespace dpi {

/**
 * @brief Zero-allocation stream calculator for per-flow statistical and behavioral metrics.
 */
class FlowBehavioralProfiler {
public:
    /**
     * @brief Updates stream metrics for a flow upon packet arrival using Welford's algorithm.
     * @param metrics In-out flow behavioral metrics struct.
     * @param packet Parsed packet reference.
     * @param timestamp_us Packet timestamp in microseconds.
     * @param is_forward True if packet is in forward client->server direction.
     */
    static void update_metrics(BehavioralMetrics& metrics,
                               const ParsedPacket& packet,
                               uint64_t timestamp_us,
                               bool is_forward) noexcept;
};

} // namespace dpi

#endif // DPI_BEHAVIORAL_PROFILER_H
