#include "dpi/rules/rule_types.h"
#include <algorithm>
#include <cctype>

namespace dpi {

std::string_view rule_action_to_string(RuleAction action) noexcept {
    switch (action) {
        case RuleAction::Allow:
            return "ALLOW";
        case RuleAction::Block:
            return "BLOCK";
        case RuleAction::Alert:
            return "ALERT";
        case RuleAction::Log:
            return "LOG";
        default:
            return "ALLOW";
    }
}

RuleAction string_to_rule_action(std::string_view str) noexcept {
    std::string upper;
    upper.reserve(str.size());
    for (char c : str) {
        upper.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    }

    if (upper == "BLOCK" || upper == "DROP" || upper == "DENY") {
        return RuleAction::Block;
    }
    if (upper == "ALERT") {
        return RuleAction::Alert;
    }
    if (upper == "LOG") {
        return RuleAction::Log;
    }
    return RuleAction::Allow;
}

} // namespace dpi
