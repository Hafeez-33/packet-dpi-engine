#include "dpi/risk/risk_engine.h"
#include "dpi/risk/behavioral_profiler.h"

namespace dpi {

RiskEngine::RiskEngine(const RiskConfig& config)
    : config_(config),
      beaconing_detector_(config.beaconing),
      exfiltration_detector_(config.exfiltration),
      risk_scorer_(config.weights),
      host_profiler_(config.max_host_profiles) {}

void RiskEngine::evaluate_flow(FlowEntry& flow,
                               const ParsedPacket& packet,
                               uint64_t timestamp_us,
                               bool is_forward,
                               const std::vector<SecurityAlert>& alerts,
                               RuleAction policy_action) {
    if (!config_.enabled || !packet.is_valid()) {
        return;
    }

    // 1. Update rolling stream metrics using Welford's algorithm
    BehavioralMetrics& metrics = flow.behavioral_metrics();
    FlowBehavioralProfiler::update_metrics(metrics, packet, timestamp_us, is_forward);

    // 2. Evaluate behavioral anomaly detectors
    beaconing_detector_.evaluate(metrics);
    exfiltration_detector_.evaluate(metrics);

    // 3. Compute normalized composite risk score
    uint16_t dst_port = packet.is_tcp() ? packet.tcp.dst_port : (packet.is_udp() ? packet.udp.dst_port : 0);
    FlowRiskScore score = risk_scorer_.calculate_score(metrics, flow.l7_metadata(), policy_action, alerts, dst_port);
    flow.set_risk_score(score);

    // 4. Update host risk profiles for client and server
    const auto& key = flow.key();
    host_profiler_.update_host_risk(key.src.ip, score.score, metrics.is_beaconing, metrics.is_exfiltration, timestamp_us);
    host_profiler_.update_host_risk(key.dst.ip, score.score, metrics.is_beaconing, metrics.is_exfiltration, timestamp_us);
}

std::vector<HostRiskProfile> RiskEngine::get_top_hosts(size_t limit) const {
    return host_profiler_.get_top_hosts(limit);
}

void RiskEngine::clear() noexcept {
    host_profiler_.clear();
}

} // namespace dpi
