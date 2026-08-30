#include "dpi/rules/ip_matcher.h"
#include <charconv>

namespace dpi {

IpMatcher IpMatcher::parse(std::string_view cidr_str) noexcept {
    IpMatcher matcher;
    if (cidr_str.empty() || cidr_str == "*" || cidr_str == "ANY" || cidr_str == "any") {
        matcher.is_any_ = true;
        matcher.is_valid_ = true;
        return matcher;
    }

    matcher.is_any_ = false;

    // Check for CIDR slash
    size_t slash_pos = cidr_str.find('/');
    std::string_view ip_part = (slash_pos != std::string_view::npos) ? cidr_str.substr(0, slash_pos) : cidr_str;
    std::string_view prefix_part = (slash_pos != std::string_view::npos) ? cidr_str.substr(slash_pos + 1) : "";

    // Determine if IPv4 or IPv6
    if (ip_part.find(':') != std::string_view::npos) {
        // IPv6
        matcher.is_ipv4_ = false;
        auto ipv6_opt = IPv6Address::from_string(ip_part);
        if (!ipv6_opt.has_value()) {
            matcher.is_valid_ = false;
            return matcher;
        }

        uint8_t prefix = 128;
        if (!prefix_part.empty()) {
            unsigned int p = 0;
            auto [ptr, ec] = std::from_chars(prefix_part.data(), prefix_part.data() + prefix_part.size(), p);
            if (ec != std::errc() || p > 128) {
                matcher.is_valid_ = false;
                return matcher;
            }
            prefix = static_cast<uint8_t>(p);
        }

        matcher.prefix_len_ = prefix;
        matcher.ipv6_net_ = ipv6_opt->bytes;

        // Build 128-bit netmask
        matcher.ipv6_mask_.fill(0);
        size_t full_bytes = prefix / 8;
        for (size_t i = 0; i < full_bytes && i < 16; ++i) {
            matcher.ipv6_mask_[i] = 0xFF;
        }
        size_t rem_bits = prefix % 8;
        if (rem_bits > 0 && full_bytes < 16) {
            matcher.ipv6_mask_[full_bytes] = static_cast<uint8_t>(0xFF << (8 - rem_bits));
        }

        // Apply mask to network address
        for (size_t i = 0; i < 16; ++i) {
            matcher.ipv6_net_[i] &= matcher.ipv6_mask_[i];
        }
        matcher.is_valid_ = true;
    } else {
        // IPv4
        matcher.is_ipv4_ = true;
        auto ipv4_opt = IPv4Address::from_string(ip_part);
        if (!ipv4_opt.has_value()) {
            matcher.is_valid_ = false;
            return matcher;
        }

        uint8_t prefix = 32;
        if (!prefix_part.empty()) {
            unsigned int p = 0;
            auto [ptr, ec] = std::from_chars(prefix_part.data(), prefix_part.data() + prefix_part.size(), p);
            if (ec != std::errc() || p > 32) {
                matcher.is_valid_ = false;
                return matcher;
            }
            prefix = static_cast<uint8_t>(p);
        }

        matcher.prefix_len_ = prefix;
        uint32_t mask = (prefix == 0) ? 0 : (0xFFFFFFFFu << (32 - prefix));
        matcher.ipv4_mask_ = mask;
        matcher.ipv4_net_ = ipv4_opt->to_u32() & mask;
        matcher.is_valid_ = true;
    }

    return matcher;
}

bool IpMatcher::matches(const IPAddress& ip) const noexcept {
    if (!is_valid_) return false;
    if (is_any_) return true;

    if (is_ipv4_) {
        if (!ip.is_v4()) return false;
        return (ip.v4().to_u32() & ipv4_mask_) == ipv4_net_;
    } else {
        if (!ip.is_v6()) return false;
        const auto& addr_bytes = ip.v6().bytes;
        for (size_t i = 0; i < 16; ++i) {
            if ((addr_bytes[i] & ipv6_mask_[i]) != ipv6_net_[i]) {
                return false;
            }
        }
        return true;
    }
}

} // namespace dpi
