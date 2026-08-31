#ifndef DPI_RULES_PORT_MATCHER_H
#define DPI_RULES_PORT_MATCHER_H

#include <cstdint>
#include <string_view>
#include <utility>
#include <vector>

namespace dpi {

/**
 * @brief Matches transport ports against single values, ranges, and comma-separated lists.
 */
class PortMatcher {
public:
    PortMatcher() noexcept : is_any_(true), is_valid_(true) {}

    /**
     * @brief Parses a port expression (e.g. "80", "8000-8080", "80,443,8080", "any").
     */
    static PortMatcher parse(std::string_view port_expr) noexcept;

    bool is_any() const noexcept { return is_any_; }
    bool is_valid() const noexcept { return is_valid_; }

    /**
     * @brief Checks if a given transport port matches this matcher.
     */
    bool matches(uint16_t port) const noexcept;

private:
    bool is_any_{true};
    bool is_valid_{true};
    std::vector<std::pair<uint16_t, uint16_t>> ranges_{};
};

} // namespace dpi

#endif // DPI_RULES_PORT_MATCHER_H
