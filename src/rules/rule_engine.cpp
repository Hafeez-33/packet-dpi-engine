#include "dpi/rules/rule_engine.h"
#include <algorithm>
#include <cctype>

namespace dpi {

static uint8_t parse_protocol_str(std::string_view proto_str) noexcept {
    if (proto_str.empty() || proto_str == "ANY" || proto_str == "any" || proto_str == "*") {
        return 0;
    }
    std::string upper;
    for (char c : proto_str) {
        upper.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    }
    if (upper == "TCP" || upper == "6") return 6;
    if (upper == "UDP" || upper == "17") return 17;
    return 0;
}

static std::pair<AppProtocol, bool> parse_app_protocol_str(std::string_view app_str) noexcept {
    if (app_str.empty() || app_str == "ANY" || app_str == "any" || app_str == "*") {
        return {AppProtocol::Unknown, true}; // Match any
    }
    std::string upper;
    for (char c : app_str) {
        upper.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    }
    if (upper == "TLS") return {AppProtocol::TLS, false};
    if (upper == "HTTP") return {AppProtocol::HTTP, false};
    if (upper == "DNS") return {AppProtocol::DNS, false};
    return {AppProtocol::Unknown, false};
}

// -------------------------------------------------------------
// CompiledRuleSet Implementation
// -------------------------------------------------------------

CompiledRuleSet::CompiledRuleSet(std::vector<CompiledRule> rules, RuleAction default_action) noexcept
    : rules_(std::move(rules)), default_action_(default_action) {
    // Sort rules deterministically: ascending priority (lower number = higher priority), then by id
    std::stable_sort(rules_.begin(), rules_.end(), [](const CompiledRule& a, const CompiledRule& b) {
        if (a.priority != b.priority) {
            return a.priority < b.priority;
        }
        return a.id < b.id;
    });
}

static bool match_endpoints(const CompiledRule& r, const FlowKey& key) noexcept {
    // Check transport protocol
    if (r.protocol != 0 && r.protocol != key.protocol) {
        return false;
    }

    // Direction 1: rule.src -> key.src, rule.dst -> key.dst
    bool dir1_ip = r.src_ip.matches(key.src.ip) && r.dst_ip.matches(key.dst.ip);
    bool dir1_port = r.src_port.matches(key.src.port) && r.dst_port.matches(key.dst.port);

    if (dir1_ip && dir1_port) {
        return true;
    }

    // Direction 2: rule.src -> key.dst, rule.dst -> key.src (bidirectional normalization)
    bool dir2_ip = r.src_ip.matches(key.dst.ip) && r.dst_ip.matches(key.src.ip);
    bool dir2_port = r.src_port.matches(key.dst.port) && r.dst_port.matches(key.src.port);

    return dir2_ip && dir2_port;
}

PolicyVerdict CompiledRuleSet::evaluate_l3_l4(const FlowKey& key) const noexcept {
    for (const auto& r : rules_) {
        if (!r.enabled) continue;
        if (r.has_l7_criteria) continue; // Requires L7 inspection

        if (match_endpoints(r, key)) {
            PolicyVerdict v;
            v.action = r.action;
            v.matched_rule_id = r.id;
            v.matched_rule_name = r.name;
            v.reason = "L3/L4 Rule Match: " + r.name;
            v.is_final = true;
            return v;
        }
    }

    // Provisional verdict before L7 inspection is complete
    PolicyVerdict v;
    v.action = default_action_;
    v.matched_rule_id = 0;
    v.matched_rule_name = "";
    v.reason = "Provisional L3/L4 Default Action";
    v.is_final = false;
    return v;
}

PolicyVerdict CompiledRuleSet::evaluate_l7(const FlowKey& key, const L7Metadata& l7_meta) const noexcept {
    for (const auto& r : rules_) {
        if (!r.enabled) continue;

        if (!match_endpoints(r, key)) {
            continue;
        }

        // Domain matching
        if (!r.domain.is_any()) {
            if (!r.domain.matches(l7_meta.hostname)) {
                continue;
            }
        }

        // App protocol matching
        if (!r.match_any_app) {
            if (r.app_protocol != l7_meta.protocol) {
                continue;
            }
        }

        PolicyVerdict v;
        v.action = r.action;
        v.matched_rule_id = r.id;
        v.matched_rule_name = r.name;
        v.reason = r.has_l7_criteria ? ("L7 Rule Match: " + r.name) : ("L3/L4 Rule Match: " + r.name);
        v.is_final = true;
        return v;
    }

    PolicyVerdict v;
    v.action = default_action_;
    v.matched_rule_id = 0;
    v.matched_rule_name = "";
    v.reason = "Default Policy Action";
    v.is_final = true;
    return v;
}

// -------------------------------------------------------------
// RuleEngine Implementation
// -------------------------------------------------------------

RuleEngine::RuleEngine() noexcept {
    rebuild_active_ruleset();
}

CompiledRule RuleEngine::compile_rule(const Rule& r) noexcept {
    CompiledRule cr;
    cr.id = r.id;
    cr.name = r.name;
    cr.priority = r.priority;
    cr.enabled = r.enabled;
    cr.action = r.action;

    cr.src_ip = IpMatcher::parse(r.src_ip_cidr);
    cr.dst_ip = IpMatcher::parse(r.dst_ip_cidr);
    cr.src_port = PortMatcher::parse(r.src_port_range);
    cr.dst_port = PortMatcher::parse(r.dst_port_range);
    cr.protocol = parse_protocol_str(r.transport_protocol);

    cr.domain = DomainMatcher::parse(r.domain_pattern);
    auto [app_proto, any_app] = parse_app_protocol_str(r.app_protocol);
    cr.app_protocol = app_proto;
    cr.match_any_app = any_app;

    cr.has_l7_criteria = !cr.domain.is_any() || !cr.match_any_app;
    return cr;
}

void RuleEngine::rebuild_active_ruleset() noexcept {
    std::vector<CompiledRule> compiled;
    compiled.reserve(raw_rules_.size());
    for (const auto& r : raw_rules_) {
        compiled.push_back(compile_rule(r));
    }
    active_rules_ = std::make_shared<const CompiledRuleSet>(std::move(compiled), default_action_);
}

RuleLoadResult RuleEngine::load_rules_from_file(const std::string& filepath) noexcept {
    RuleLoadResult res = RuleParser::parse_file(filepath);
    if (res.success) {
        std::lock_guard<std::mutex> lock(mutex_);
        raw_rules_ = res.rules;
        default_action_ = res.default_action;
        rebuild_active_ruleset();
    }
    return res;
}

RuleLoadResult RuleEngine::load_rules_from_json(std::string_view json_content) noexcept {
    RuleLoadResult res = RuleParser::parse_string(json_content);
    if (res.success) {
        std::lock_guard<std::mutex> lock(mutex_);
        raw_rules_ = res.rules;
        default_action_ = res.default_action;
        rebuild_active_ruleset();
    }
    return res;
}

bool RuleEngine::add_rule(const Rule& rule) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    raw_rules_.push_back(rule);
    rebuild_active_ruleset();
    return true;
}

void RuleEngine::clear_rules() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    raw_rules_.clear();
    rebuild_active_ruleset();
}

void RuleEngine::set_default_action(RuleAction action) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    default_action_ = action;
    rebuild_active_ruleset();
}

RuleAction RuleEngine::default_action() const noexcept {
    auto set = std::atomic_load(&active_rules_);
    return set ? set->default_action() : default_action_;
}

size_t RuleEngine::rule_count() const noexcept {
    auto set = std::atomic_load(&active_rules_);
    return set ? set->size() : 0;
}

PolicyVerdict RuleEngine::evaluate_l3_l4(const FlowKey& key) const noexcept {
    auto set = std::atomic_load(&active_rules_);
    if (!set) {
        return PolicyVerdict{RuleAction::Allow, 0, "", "No active ruleset", false};
    }
    return set->evaluate_l3_l4(key);
}

PolicyVerdict RuleEngine::evaluate_l7(const FlowKey& key, const L7Metadata& l7_meta) const noexcept {
    auto set = std::atomic_load(&active_rules_);
    if (!set) {
        return PolicyVerdict{RuleAction::Allow, 0, "", "No active ruleset", true};
    }
    return set->evaluate_l7(key, l7_meta);
}

PolicyVerdict RuleEngine::evaluate(const FlowEntry& flow) const noexcept {
    if (flow.is_classified() || flow.is_dpi_complete()) {
        return evaluate_l7(flow.key(), flow.l7_metadata());
    }
    return evaluate_l3_l4(flow.key());
}

PolicyVerdict RuleEngine::evaluate(const ParsedPacket& packet, const L7Metadata& l7_meta) const noexcept {
    auto [key, dir] = FlowKey::from_packet(packet);
    if (!key.src.ip.is_valid() || !key.dst.ip.is_valid()) {
        return PolicyVerdict{default_action(), 0, "", "Invalid packet key", true};
    }
    if (l7_meta.is_classified) {
        return evaluate_l7(key, l7_meta);
    }
    return evaluate_l3_l4(key);
}

} // namespace dpi
