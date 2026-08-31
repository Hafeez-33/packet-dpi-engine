#ifndef DPI_RISK_ENGINE_H
#define DPI_RISK_ENGINE_H

#include "dpi/risk/risk_types.h"
#include "dpi/risk/risk_config.h"
#include "dpi/risk/beaconing_detector.h"
#include "dpi/risk/exfiltration_detector.h"
#include "dpi/risk/risk_scorer.h"
#include "dpi/risk/host_risk_profiler.h"
#include "dpi/flow/flow_entry.h"
#include "dpi/protocols/protocol_types.h"
#include "dpi/threat/threat_types.h"
#include <vector>

namespace dpi {

/**
 * @brief Master coordinator for worker-local flow behavioral profiling and risk scoring.
 */
class RiskEngine {
public:
    explicit RiskEngine(const RiskConfig& config = RiskConfig{});

    /**
     * @brief Updates behavioral statistics and calculates composite risk score for a flow.
     */
    void evaluate_flow(FlowEntry& flow,
                       const ParsedPacket& packet,
                       uint64_t timestamp_us,
                       bool is_forward,
                       const std::vector<SecurityAlert>& alerts,
                       RuleAction policy_action);

    /**
     * @brief Retrieves top risky host profiles tracked by this worker.
     */
    std::vector<HostRiskProfile> get_top_hosts(size_t limit = 20) const;

    /**
     * @brief Resets/clears state.
     */
    void clear() noexcept;

    /**
     * @brief Returns current config.
     */
    const RiskConfig& config() const noexcept { return config_; }

private:
    RiskConfig config_;
    BeaconingDetector beaconing_detector_;
    ExfiltrationDetector exfiltration_detector_;
    RiskScorer risk_scorer_;
    HostRiskProfiler host_profiler_;
};

} // namespace dpi

#endif // DPI_RISK_ENGINE_H
