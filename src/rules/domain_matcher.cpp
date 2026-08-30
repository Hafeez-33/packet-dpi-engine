#include "dpi/rules/domain_matcher.h"
#include <algorithm>
#include <cctype>

namespace dpi {

static std::string to_lower_str(std::string_view s) {
    std::string res;
    res.reserve(s.size());
    for (char c : s) {
        res.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return res;
}

static bool glob_match(std::string_view text, std::string_view pattern) noexcept {
    size_t t_idx = 0, p_idx = 0;
    size_t star_idx = std::string_view::npos, match_idx = 0;

    while (t_idx < text.size()) {
        if (p_idx < pattern.size() && (pattern[p_idx] == '?' || pattern[p_idx] == text[t_idx])) {
            ++t_idx;
            ++p_idx;
        } else if (p_idx < pattern.size() && pattern[p_idx] == '*') {
            star_idx = p_idx;
            match_idx = t_idx;
            ++p_idx;
        } else if (star_idx != std::string_view::npos) {
            p_idx = star_idx + 1;
            ++match_idx;
            t_idx = match_idx;
        } else {
            return false;
        }
    }

    while (p_idx < pattern.size() && pattern[p_idx] == '*') {
        ++p_idx;
    }

    return p_idx == pattern.size();
}

DomainMatcher DomainMatcher::parse(std::string_view pattern) noexcept {
    DomainMatcher matcher;
    if (pattern.empty() || pattern == "*" || pattern == "ANY" || pattern == "any") {
        matcher.is_any_ = true;
        matcher.is_valid_ = true;
        return matcher;
    }

    matcher.is_any_ = false;
    matcher.pattern_ = to_lower_str(pattern);

    if (matcher.pattern_.size() >= 2 && matcher.pattern_[0] == '*' && matcher.pattern_[1] == '.') {
        matcher.is_suffix_wildcard_ = true;
        matcher.suffix_ = matcher.pattern_.substr(2); // e.g. "tiktok.com"
    } else {
        matcher.is_suffix_wildcard_ = false;
    }

    matcher.is_valid_ = true;
    return matcher;
}

bool DomainMatcher::matches(std::string_view domain) const noexcept {
    if (!is_valid_) return false;
    if (is_any_) return true;
    if (domain.empty()) return false;

    std::string lower_domain = to_lower_str(domain);

    // Fast path: *.domain.com matching
    if (is_suffix_wildcard_) {
        // Matches exact base domain: "tiktok.com" matches "*.tiktok.com"
        if (lower_domain == suffix_) {
            return true;
        }
        // Matches subdomains: "v16.api.tiktok.com" ends with ".tiktok.com"
        std::string dot_suffix = "." + suffix_;
        if (lower_domain.size() > dot_suffix.size()) {
            if (lower_domain.compare(lower_domain.size() - dot_suffix.size(), dot_suffix.size(), dot_suffix) == 0) {
                return true;
            }
        }
        return false;
    }

    // General exact or glob matching
    return glob_match(lower_domain, pattern_);
}

} // namespace dpi
