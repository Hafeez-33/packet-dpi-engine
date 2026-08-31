#ifndef DPI_RISK_SCORER_H
#define DPI_RISK_SCORER_H

#include "dpi/risk/risk_types.h"
#include "dpi/risk/risk_config.h"
#include "dpi/threat/threat_types.h"
#include "dpi/rules/rule_types.h"
#include "dpi/dpi/l7_types.h"
#include <vector>

namespace dpi {

/**
 * @brief Computes normalized composite risk scores (0-100) based on DPI, policy, threat, and behavioral inputs.
 */
class RiskScorer {
public:
    explicit RiskScorer(const RiskScoringWeights& weights = RiskScoringWeights{}) noexcept
        : weights_(weights) {}

    /**
     * @brief Computes the normalized flow risk score and assigns contributing factor strings.
     */
    FlowRiskScore calculate_score(const BehavioralMetrics& metrics,
                                  const L7Metadata& l7,
                                  RuleAction policy_action,
                                  const std::vector<SecurityAlert>& flow_alerts,
                                  uint16_t dst_port) const;

private:
    RiskScoringWeights weights_;
};

} // namespace dpi

#endif // DPI_RISK_SCORER_H
