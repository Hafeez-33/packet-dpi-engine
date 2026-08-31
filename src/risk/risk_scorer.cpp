#include "dpi/risk/risk_scorer.h"
#include <algorithm>

namespace dpi {

FlowRiskScore RiskScorer::calculate_score(const BehavioralMetrics& metrics,
                                          const L7Metadata& l7,
                                          RuleAction policy_action,
                                          const std::vector<SecurityAlert>& flow_alerts,
                                          uint16_t dst_port) const {
    FlowRiskScore result;
    uint32_t raw_score = 0;

    // 1. Evaluate Stage 8 Threat Alerts
    for (const auto& alert : flow_alerts) {
        if (result.contributing_factors.size() < 5) {
            result.contributing_factors.push_back("Threat Alert: " + alert.signature_name);
        }

        switch (alert.severity) {
            case AlertSeverity::Critical:
                raw_score += weights_.threat_alert_critical;
                break;
            case AlertSeverity::High:
                raw_score += weights_.threat_alert_high;
                break;
            case AlertSeverity::Medium:
                raw_score += weights_.threat_alert_medium;
                break;
            case AlertSeverity::Low:
            case AlertSeverity::Info:
                raw_score += weights_.threat_alert_low;
                break;
        }
    }

    // 2. Evaluate Stage 5 Policy Actions
    if (policy_action == RuleAction::Block) {
        raw_score += weights_.policy_blocked;
        if (result.contributing_factors.size() < 5) {
            result.contributing_factors.push_back("Security Policy: Traffic Blocked");
        }
    } else if (policy_action == RuleAction::Alert) {
        raw_score += weights_.policy_alert;
        if (result.contributing_factors.size() < 5) {
            result.contributing_factors.push_back("Security Policy: Traffic Flagged");
        }
    }

    // 3. Evaluate Behavioral Anomalies (Beaconing / Exfiltration)
    if (metrics.is_beaconing) {
        raw_score += weights_.beaconing_detected;
        if (result.contributing_factors.size() < 5) {
            result.contributing_factors.push_back("C2 Beaconing: Periodic low-jitter heartbeat");
        }
    }

    if (metrics.is_exfiltration) {
        raw_score += weights_.exfiltration_detected;
        if (result.contributing_factors.size() < 5) {
            result.contributing_factors.push_back("Data Exfiltration: High-volume asymmetric upload");
        }
    }

    // 4. Protocol / Port Heuristics
    if (!l7.is_classified && dst_port >= 1024 && metrics.fwd_bytes > 5000) {
        raw_score += weights_.unclassified_high_port;
        if (result.contributing_factors.size() < 5) {
            result.contributing_factors.push_back("Unclassified protocol on high port");
        }
    }

    // 5. Large unacknowledged burst heuristic (>90% large packets with 0 return)
    uint32_t total_pkts = metrics.fwd_packets + metrics.rev_packets;
    if (total_pkts >= 10 && metrics.rev_packets == 0 && metrics.large_packets > (metrics.fwd_packets * 8 / 10)) {
        raw_score += weights_.large_packet_burst;
        if (result.contributing_factors.size() < 5) {
            result.contributing_factors.push_back("High-volume unidirectional packet burst");
        }
    }

    // Clamp score to 0 - 100
    uint8_t final_score = static_cast<uint8_t>(std::min<uint32_t>(100, raw_score));
    result.score = final_score;

    // Assign categorical risk level
    if (final_score >= 80) {
        result.level = RiskLevel::Critical;
    } else if (final_score >= 60) {
        result.level = RiskLevel::High;
    } else if (final_score >= 40) {
        result.level = RiskLevel::Medium;
    } else if (final_score >= 20) {
        result.level = RiskLevel::Low;
    } else {
        result.level = RiskLevel::None;
    }

    return result;
}

} // namespace dpi
