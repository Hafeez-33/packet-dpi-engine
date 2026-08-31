#ifndef DPI_RULES_RULE_TYPES_H
#define DPI_RULES_RULE_TYPES_H

#include "dpi/dpi/l7_types.h"
#include <cstdint>
#include <string>
#include <string_view>

namespace dpi {

/**
 * @brief Actions enforceable by the Rule & Policy Engine.
 */
enum class RuleAction : uint8_t {
    Allow = 0,    // Permit traffic
    Block,        // Drop/block traffic
    Alert,        // Generate security alert event (traffic continues)
    Log           // Log telemetry record (traffic continues)
};

std::string_view rule_action_to_string(RuleAction action) noexcept;
RuleAction string_to_rule_action(std::string_view str) noexcept;

/**
 * @brief Policy verdict produced from rule evaluation.
 */
struct PolicyVerdict {
    RuleAction action{RuleAction::Allow};
    uint32_t matched_rule_id{0};
    std::string matched_rule_name{};
    std::string reason{};
    bool is_final{false};       // True if determined by explicit rule or final L7 inspection

    bool is_blocked() const noexcept { return action == RuleAction::Block; }
    bool is_allowed() const noexcept { return action == RuleAction::Allow; }
};

/**
 * @brief Represents a single filtering policy rule.
 */
struct Rule {
    uint32_t id{0};                         // Unique numeric rule ID
    std::string name{};                     // Human-readable rule description
    uint32_t priority{100};                 // Lower numeric value = higher evaluation precedence
    bool enabled{true};                     // Active toggle
    RuleAction action{RuleAction::Block};   // Action to apply on match

    // L3 / L4 Criteria (empty/any = wildcard match)
    std::string src_ip_cidr{};              // e.g. "192.168.1.0/24" or "2001:db8::/32"
    std::string dst_ip_cidr{};              // e.g. "10.0.0.0/8"
    std::string src_port_range{};           // e.g. "1024-65535" or "80"
    std::string dst_port_range{};           // e.g. "80,443,8080"
    std::string transport_protocol{};       // "TCP", "UDP", "ANY"

    // L7 Criteria (evaluated when L7 metadata is available)
    std::string domain_pattern{};           // e.g. "*.tiktok.com", "doubleclick.net"
    std::string app_protocol{};             // "TLS", "HTTP", "DNS", "ANY"

    /**
     * @brief Checks whether the rule requires Layer-7 metadata for evaluation.
     */
    bool has_l7_criteria() const noexcept {
        return !domain_pattern.empty() || (!app_protocol.empty() && app_protocol != "ANY");
    }
};

} // namespace dpi

#endif // DPI_RULES_RULE_TYPES_H
