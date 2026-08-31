#include "dpi/risk/exfiltration_detector.h"

namespace dpi {

bool ExfiltrationDetector::evaluate(BehavioralMetrics& metrics) const noexcept {
    if (!config_.enabled) {
        metrics.is_exfiltration = false;
        return false;
    }

    // Minimum forward/outbound byte volume threshold
    if (metrics.fwd_bytes < config_.min_fwd_bytes) {
        metrics.is_exfiltration = false;
        return false;
    }

    // Byte ratio threshold (fwd_bytes / rev_bytes)
    if (metrics.byte_ratio >= config_.min_byte_ratio) {
        metrics.is_exfiltration = true;
        metrics.exfiltration_ratio = metrics.byte_ratio;
        return true;
    }

    metrics.is_exfiltration = false;
    return false;
}

} // namespace dpi
