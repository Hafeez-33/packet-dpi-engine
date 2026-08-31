#ifndef DPI_RULES_IP_MATCHER_H
#define DPI_RULES_IP_MATCHER_H

#include "dpi/flow/ip_address.h"
#include <cstdint>
#include <string>
#include <string_view>

namespace dpi {

/**
 * @brief Matches IPv4 and IPv6 addresses against exact IPs or CIDR subnet prefixes.
 */
class IpMatcher {
public:
    IpMatcher() noexcept : is_any_(true), is_valid_(true) {}

    /**
     * @brief Parses an exact IP address or CIDR notation string (e.g. "192.168.1.0/24", "2001:db8::/32").
     */
    static IpMatcher parse(std::string_view cidr_str) noexcept;

    bool is_any() const noexcept { return is_any_; }
    bool is_valid() const noexcept { return is_valid_; }
    bool is_ipv4() const noexcept { return !is_any_ && is_ipv4_; }
    bool is_ipv6() const noexcept { return !is_any_ && !is_ipv4_; }

    /**
     * @brief Checks if a given IPAddress matches this matcher.
     */
    bool matches(const IPAddress& ip) const noexcept;

private:
    bool is_any_{true};
    bool is_valid_{true};
    bool is_ipv4_{true};
    uint8_t prefix_len_{0};

    // IPv4 representation
    uint32_t ipv4_net_{0};
    uint32_t ipv4_mask_{0};

    // IPv6 representation
    std::array<uint8_t, 16> ipv6_net_{};
    std::array<uint8_t, 16> ipv6_mask_{};
};

} // namespace dpi

#endif // DPI_RULES_IP_MATCHER_H
