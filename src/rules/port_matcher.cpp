#include "dpi/rules/port_matcher.h"
#include <charconv>
#include <sstream>

namespace dpi {

PortMatcher PortMatcher::parse(std::string_view port_expr) noexcept {
    PortMatcher matcher;
    if (port_expr.empty() || port_expr == "*" || port_expr == "ANY" || port_expr == "any" || port_expr == "0") {
        matcher.is_any_ = true;
        matcher.is_valid_ = true;
        return matcher;
    }

    matcher.is_any_ = false;

    // Split by commas
    size_t start = 0;
    while (start < port_expr.size()) {
        size_t comma = port_expr.find(',', start);
        if (comma == std::string_view::npos) comma = port_expr.size();

        std::string_view token = port_expr.substr(start, comma - start);
        // Trim whitespace
        while (!token.empty() && (token.front() == ' ' || token.front() == '\t')) token.remove_prefix(1);
        while (!token.empty() && (token.back() == ' ' || token.back() == '\t')) token.remove_suffix(1);

        if (!token.empty()) {
            size_t dash = token.find('-');
            if (dash != std::string_view::npos) {
                std::string_view min_str = token.substr(0, dash);
                std::string_view max_str = token.substr(dash + 1);

                unsigned int min_p = 0, max_p = 0;
                auto [p1, ec1] = std::from_chars(min_str.data(), min_str.data() + min_str.size(), min_p);
                auto [p2, ec2] = std::from_chars(max_str.data(), max_str.data() + max_str.size(), max_p);

                if (ec1 != std::errc() || ec2 != std::errc() || min_p > 65535 || max_p > 65535 || min_p > max_p) {
                    matcher.is_valid_ = false;
                    return matcher;
                }

                matcher.ranges_.emplace_back(static_cast<uint16_t>(min_p), static_cast<uint16_t>(max_p));
            } else {
                unsigned int p = 0;
                auto [p1, ec1] = std::from_chars(token.data(), token.data() + token.size(), p);
                if (ec1 != std::errc() || p > 65535) {
                    matcher.is_valid_ = false;
                    return matcher;
                }

                matcher.ranges_.emplace_back(static_cast<uint16_t>(p), static_cast<uint16_t>(p));
            }
        }

        start = comma + 1;
    }

    if (matcher.ranges_.empty()) {
        matcher.is_any_ = true;
    }

    matcher.is_valid_ = true;
    return matcher;
}

bool PortMatcher::matches(uint16_t port) const noexcept {
    if (!is_valid_) return false;
    if (is_any_) return true;

    for (const auto& range : ranges_) {
        if (port >= range.first && port <= range.second) {
            return true;
        }
    }
    return false;
}

} // namespace dpi
