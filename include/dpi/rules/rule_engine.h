#ifndef DPI_RULES_RULE_ENGINE_H
#define DPI_RULES_RULE_ENGINE_H

#include "dpi/flow/flow_entry.h"
#include "dpi/flow/flow_key.h"
#include "dpi/protocols/parsed_packet.h"
#include "dpi/rules/domain_matcher.h"
#include "dpi/rules/ip_matcher.h"
#include "dpi/rules/port_matcher.h"
#include "dpi/rules/rule_parser.h"
#include "dpi/rules/rule_types.h"
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace dpi {

/**
 * @brief Internal compiled rule representation optimized for fast evaluation.
 */
struct CompiledRule {
    uint32_t id{0};
    std::string name{};
    uint32_t priority{100};
    bool enabled{true};
    RuleAction action{RuleAction::Block};

    IpMatcher src_ip{};
    IpMatcher dst_ip{};
    PortMatcher src_port{};
    PortMatcher dst_port{};
    uint8_t protocol{0}; // 0 = Any, 6 = TCP, 17 = UDP

    DomainMatcher domain{};
    AppProtocol app_protocol{AppProtocol::Unknown};
    bool match_any_app{true};
    bool has_l7_criteria{false};
};

/**
 * @brief Immutable compiled rule set snapshot for deterministic evaluation.
 */
class CompiledRuleSet {
public:
    CompiledRuleSet(std::vector<CompiledRule> rules, RuleAction default_action) noexcept;

    RuleAction default_action() const noexcept { return default_action_; }
    const std::vector<CompiledRule>& rules() const noexcept { return rules_; }
    size_t size() const noexcept { return rules_.size(); }

    PolicyVerdict evaluate_l3_l4(const FlowKey& key) const noexcept;
    PolicyVerdict evaluate_l7(const FlowKey& key, const L7Metadata& l7_meta) const noexcept;

private:
    std::vector<CompiledRule> rules_{};
    RuleAction default_action_{RuleAction::Allow};
};

/**
 * @brief High-performance, deterministic Rule & Policy Engine.
 */
class RuleEngine {
public:
    RuleEngine() noexcept;

    /**
     * @brief Loads and compiles rules from a JSON configuration file.
     */
    RuleLoadResult load_rules_from_file(const std::string& filepath) noexcept;

    /**
     * @brief Loads and compiles rules from a JSON string.
     */
    RuleLoadResult load_rules_from_json(std::string_view json_content) noexcept;

    /**
     * @brief Adds a single rule to the active configuration.
     */
    bool add_rule(const Rule& rule) noexcept;

    /**
     * @brief Clears all rules and resets default action.
     */
    void clear_rules() noexcept;

    /**
     * @brief Sets the default policy action applied when no rules match.
     */
    void set_default_action(RuleAction action) noexcept;
    RuleAction default_action() const noexcept;

    size_t rule_count() const noexcept;

    /**
     * @brief Evaluates provisional L3/L4 5-tuple criteria against active rules.
     */
    PolicyVerdict evaluate_l3_l4(const FlowKey& key) const noexcept;

    /**
     * @brief Evaluates full L7 criteria (domain, app protocol) and 5-tuple against active rules.
     */
    PolicyVerdict evaluate_l7(const FlowKey& key, const L7Metadata& l7_meta) const noexcept;

    /**
     * @brief Evaluates an active flow entry taking its current inspection stage into account.
     */
    PolicyVerdict evaluate(const FlowEntry& flow) const noexcept;

    /**
     * @brief Evaluates a parsed packet and associated L7 metadata.
     */
    PolicyVerdict evaluate(const ParsedPacket& packet, const L7Metadata& l7_meta) const noexcept;

private:
    static CompiledRule compile_rule(const Rule& r) noexcept;
    void rebuild_active_ruleset() noexcept;

    mutable std::mutex mutex_{};
    std::vector<Rule> raw_rules_{};
    RuleAction default_action_{RuleAction::Allow};
    std::shared_ptr<const CompiledRuleSet> active_rules_{};
};

} // namespace dpi

#endif // DPI_RULES_RULE_ENGINE_H
