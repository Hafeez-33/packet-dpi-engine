#ifndef DPI_BEACONING_DETECTOR_H
#define DPI_BEACONING_DETECTOR_H

#include "dpi/risk/risk_types.h"
#include "dpi/risk/risk_config.h"

namespace dpi {

/**
 * @brief Evaluates flow inter-arrival regularity to detect periodic Command & Control (C2) beaconing.
 */
class BeaconingDetector {
public:
    explicit BeaconingDetector(const BeaconingConfig& config = BeaconingConfig{}) noexcept
        : config_(config) {}

    /**
     * @brief Checks if the given flow behavioral metrics exhibit periodic low-jitter beaconing.
     * @param metrics Flow metrics.
     * @return True if beaconing communication pattern is confirmed.
     */
    bool evaluate(BehavioralMetrics& metrics) const noexcept;

private:
    BeaconingConfig config_;
};

} // namespace dpi

#endif // DPI_BEACONING_DETECTOR_H
