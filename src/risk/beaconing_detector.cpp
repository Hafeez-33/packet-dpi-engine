#include "dpi/risk/beaconing_detector.h"

namespace dpi {

bool BeaconingDetector::evaluate(BehavioralMetrics& metrics) const noexcept {
    if (!config_.enabled) {
        metrics.is_beaconing = false;
        return false;
    }

    // Require minimum number of observed intervals
    if (metrics.iat_count < config_.min_intervals) {
        metrics.is_beaconing = false;
        return false;
    }

    // Interval duration must fall within valid range
    if (metrics.mean_iat_ms < config_.min_interval_ms ||
        metrics.mean_iat_ms > config_.max_interval_ms) {
        metrics.is_beaconing = false;
        return false;
    }

    // Low coefficient of variation (stddev / mean < max_jitter_ratio) indicates periodic beaconing
    if (metrics.iat_jitter_ratio <= config_.max_jitter_ratio && metrics.iat_jitter_ratio >= 0.0) {
        metrics.is_beaconing = true;
        metrics.beacon_interval_ms = metrics.mean_iat_ms;
        metrics.beacon_jitter = metrics.iat_jitter_ratio;
        return true;
    }

    metrics.is_beaconing = false;
    return false;
}

} // namespace dpi
