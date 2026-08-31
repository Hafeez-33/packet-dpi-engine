#include "dpi/risk/host_risk_profiler.h"
#include <algorithm>

namespace dpi {

HostRiskProfiler::HostRiskProfiler(size_t max_hosts) noexcept
    : max_hosts_(max_hosts > 0 ? max_hosts : 4096) {}

void HostRiskProfiler::update_host_risk(const IPAddress& ip,
                                        uint8_t flow_risk_score,
                                        bool is_beaconing,
                                        bool is_exfiltration,
                                        uint64_t timestamp_us) {
    if (!ip.is_valid()) {
        return;
    }

    auto it = map_.find(ip);
    if (it != map_.end()) {
        // Existing host: update metrics and touch LRU
        lru_list_.erase(it->second.second);
        lru_list_.push_front(ip);
        it->second.second = lru_list_.begin();

        Entry& entry = it->second.first;
        entry.profile.total_flows++;
        entry.total_risk_sum += flow_risk_score;
        entry.profile.average_flow_risk = static_cast<double>(entry.total_risk_sum) / static_cast<double>(entry.profile.total_flows);

        if (flow_risk_score > entry.profile.max_flow_risk) {
            entry.profile.max_flow_risk = flow_risk_score;
        }
        if (flow_risk_score >= 60) {
            entry.profile.high_risk_flows++;
        }
        if (is_beaconing) {
            entry.profile.has_beaconing_flow = true;
        }
        if (is_exfiltration) {
            entry.profile.has_exfiltration_flow = true;
        }
        entry.profile.last_seen_us = timestamp_us;
    } else {
        // Evict LRU if at capacity
        if (map_.size() >= max_hosts_ && !lru_list_.empty()) {
            IPAddress lru_ip = lru_list_.back();
            lru_list_.pop_back();
            map_.erase(lru_ip);
        }

        lru_list_.push_front(ip);
        Entry new_entry{};
        new_entry.profile.ip = ip;
        new_entry.profile.total_flows = 1;
        new_entry.profile.max_flow_risk = flow_risk_score;
        new_entry.profile.average_flow_risk = flow_risk_score;
        new_entry.total_risk_sum = flow_risk_score;
        if (flow_risk_score >= 60) {
            new_entry.profile.high_risk_flows = 1;
        }
        new_entry.profile.has_beaconing_flow = is_beaconing;
        new_entry.profile.has_exfiltration_flow = is_exfiltration;
        new_entry.profile.last_seen_us = timestamp_us;

        map_.emplace(ip, std::make_pair(new_entry, lru_list_.begin()));
    }
}

std::vector<HostRiskProfile> HostRiskProfiler::get_top_hosts(size_t limit) const {
    std::vector<HostRiskProfile> result;
    result.reserve(map_.size());

    for (const auto& kv : map_) {
        result.push_back(kv.second.first.profile);
    }

    // Sort descending by max_flow_risk, then high_risk_flows, then total_flows
    std::sort(result.begin(), result.end(), [](const HostRiskProfile& a, const HostRiskProfile& b) {
        if (a.max_flow_risk != b.max_flow_risk) {
            return a.max_flow_risk > b.max_flow_risk;
        }
        if (a.high_risk_flows != b.high_risk_flows) {
            return a.high_risk_flows > b.high_risk_flows;
        }
        return a.total_flows > b.total_flows;
    });

    if (result.size() > limit) {
        result.resize(limit);
    }
    return result;
}

void HostRiskProfiler::clear() noexcept {
    lru_list_.clear();
    map_.clear();
}

} // namespace dpi
