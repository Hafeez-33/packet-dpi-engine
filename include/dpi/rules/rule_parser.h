#ifndef DPI_RULES_RULE_PARSER_H
#define DPI_RULES_RULE_PARSER_H

#include "dpi/rules/rule_types.h"
#include <string>
#include <string_view>
#include <vector>

namespace dpi {

/**
 * @brief Result object returned by RuleParser upon loading a rule configuration.
 */
struct RuleLoadResult {
    bool success{false};
    std::vector<Rule> rules{};
    RuleAction default_action{RuleAction::Allow};
    std::string error_message{};
    size_t error_line{0};
};

/**
 * @brief Safe, robust JSON configuration parser for rule tables.
 */
class RuleParser {
public:
    /**
     * @brief Parses JSON rule configuration from a string view.
     */
    static RuleLoadResult parse_string(std::string_view json_content) noexcept;

    /**
     * @brief Parses JSON rule configuration from a file path.
     */
    static RuleLoadResult parse_file(const std::string& filepath) noexcept;
};

} // namespace dpi

#endif // DPI_RULES_RULE_PARSER_H
