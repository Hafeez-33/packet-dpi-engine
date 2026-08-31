#ifndef DPI_HOST_RISK_PROFILER_H
#define DPI_HOST_RISK_PROFILER_H

#include "dpi/risk/risk_types.h"
#include <unordered_map>
#include <list>
#include <vector>

namespace dpi {

/**
 * @brief Bounded LRU aggregator tracking host endpoint risk posture.
 */
class HostRiskProfiler {
public:
    explicit HostRiskProfiler(size_t max_hosts = 4096) noexcept;

    /**
     * @brief Updates host risk profile for the given endpoint IP.
     */
    void update_host_risk(const IPAddress& ip,
                          uint8_t flow_risk_score,
                          bool is_beaconing,
                          bool is_exfiltration,
                          uint64_t timestamp_us);

    /**
     * @brief Retrieves the top risky host profiles up to the specified limit.
     */
    std::vector<HostRiskProfile> get_top_hosts(size_t limit = 20) const;

    /**
     * @brief Returns current number of tracked hosts.
     */
    size_t size() const noexcept { return map_.size(); }

    /**
     * @brief Clears all host profiles.
     */
    void clear() noexcept;

private:
    struct Entry {
        HostRiskProfile profile;
        uint64_t total_risk_sum{0};
    };

    size_t max_hosts_;
    std::list<IPAddress> lru_list_;
    std::unordered_map<IPAddress, std::pair<Entry, std::list<IPAddress>::iterator>, IPAddressHasher> map_;
};

} // namespace dpi

#endif // DPI_HOST_RISK_PROFILER_H
