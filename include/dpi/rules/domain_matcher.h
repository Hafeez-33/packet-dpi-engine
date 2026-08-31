#ifndef DPI_RULES_DOMAIN_MATCHER_H
#define DPI_RULES_DOMAIN_MATCHER_H

#include <string>
#include <string_view>

namespace dpi {

/**
 * @brief Case-insensitive exact and wildcard (*.domain.com, ads.*.com) domain matcher.
 */
class DomainMatcher {
public:
    DomainMatcher() noexcept : is_any_(true), is_valid_(true) {}

    /**
     * @brief Parses a domain pattern string.
     */
    static DomainMatcher parse(std::string_view pattern) noexcept;

    bool is_any() const noexcept { return is_any_; }
    bool is_valid() const noexcept { return is_valid_; }
    const std::string& pattern() const noexcept { return pattern_; }

    /**
     * @brief Checks if a target domain name matches this matcher pattern.
     */
    bool matches(std::string_view domain) const noexcept;

private:
    bool is_any_{true};
    bool is_valid_{true};
    bool is_suffix_wildcard_{false}; // e.g. *.example.com
    std::string pattern_{};          // Lowercase pattern
    std::string suffix_{};           // Lowercase suffix without "*."
};

} // namespace dpi

#endif // DPI_RULES_DOMAIN_MATCHER_H
