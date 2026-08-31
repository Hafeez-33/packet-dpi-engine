#ifndef DPI_EXFILTRATION_DETECTOR_H
#define DPI_EXFILTRATION_DETECTOR_H

#include "dpi/risk/risk_types.h"
#include "dpi/risk/risk_config.h"

namespace dpi {

/**
 * @brief Evaluates flow directional asymmetry to detect data exfiltration and asymmetric uploads.
 */
class ExfiltrationDetector {
public:
    explicit ExfiltrationDetector(const ExfiltrationConfig& config = ExfiltrationConfig{}) noexcept
        : config_(config) {}

    /**
     * @brief Checks if the given flow exhibits high-volume asymmetric data exfiltration.
     * @param metrics Flow behavioral metrics.
     * @return True if data exfiltration pattern is confirmed.
     */
    bool evaluate(BehavioralMetrics& metrics) const noexcept;

private:
    ExfiltrationConfig config_;
};

} // namespace dpi

#endif // DPI_EXFILTRATION_DETECTOR_H
