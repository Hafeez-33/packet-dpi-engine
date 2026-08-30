#include "dpi/threat/payload_signature_matcher.h"
#include <algorithm>
#include <cctype>

namespace dpi {

PayloadSignatureMatcher::PayloadSignatureMatcher(const SignatureConfig& config) noexcept
    : config_(config) {}

bool PayloadSignatureMatcher::add_signature(PayloadSignature sig) {
    if (signatures_.size() >= config_.max_signatures) {
        return false;
    }
    if (sig.pattern.empty() || sig.pattern.size() > config_.max_pattern_length) {
        return false;
    }
    signatures_.push_back(std::move(sig));
    return true;
}

void PayloadSignatureMatcher::load_default_signatures() {
    clear();

    // SQL Injection signatures
    add_signature({1, "SQLi: UNION SELECT", AlertSeverity::High, ThreatCategory::SqlInjection, "UNION SELECT", true, MatchTarget::AnyPayload});
    add_signature({2, "SQLi: Encoded UNION SELECT", AlertSeverity::High, ThreatCategory::SqlInjection, "UNION%20SELECT", true, MatchTarget::AnyPayload});
    add_signature({3, "SQLi: Tautology Pattern", AlertSeverity::High, ThreatCategory::SqlInjection, "' OR '1'='1", true, MatchTarget::AnyPayload});
    add_signature({4, "SQLi: Numeric Tautology", AlertSeverity::High, ThreatCategory::SqlInjection, "' OR 1=1", true, MatchTarget::AnyPayload});
    add_signature({5, "SQLi: Time-based SLEEP", AlertSeverity::High, ThreatCategory::SqlInjection, "SLEEP(", true, MatchTarget::AnyPayload});

    // Directory Traversal signatures
    add_signature({10, "Traversal: Dot-Dot-Slash", AlertSeverity::High, ThreatCategory::DirectoryTraversal, "../", false, MatchTarget::AnyPayload});
    add_signature({11, "Traversal: Dot-Dot-Backslash", AlertSeverity::High, ThreatCategory::DirectoryTraversal, "..\\", false, MatchTarget::AnyPayload});
    add_signature({12, "Traversal: Encoded %2e%2e%2f", AlertSeverity::High, ThreatCategory::DirectoryTraversal, "%2e%2e%2f", true, MatchTarget::AnyPayload});
    add_signature({13, "Traversal: Encoded %2e%2e/", AlertSeverity::High, ThreatCategory::DirectoryTraversal, "%2e%2e/", true, MatchTarget::AnyPayload});
    add_signature({14, "Traversal: /etc/passwd target", AlertSeverity::Critical, ThreatCategory::DirectoryTraversal, "/etc/passwd", true, MatchTarget::AnyPayload});

    // Malicious Recon & Exploitation Scanners
    add_signature({20, "Scanner: sqlmap User-Agent", AlertSeverity::High, ThreatCategory::SuspiciousUserAgent, "sqlmap", true, MatchTarget::UserAgent});
    add_signature({21, "Scanner: Nikto Web Scanner", AlertSeverity::High, ThreatCategory::SuspiciousUserAgent, "Nikto", true, MatchTarget::UserAgent});
    add_signature({22, "Scanner: Masscan Tool", AlertSeverity::Medium, ThreatCategory::SuspiciousUserAgent, "masscan", true, MatchTarget::UserAgent});
    add_signature({23, "Scanner: Gobuster Brute Force", AlertSeverity::Medium, ThreatCategory::SuspiciousUserAgent, "gobuster", true, MatchTarget::UserAgent});
    add_signature({24, "Scanner: DirBuster Tool", AlertSeverity::Medium, ThreatCategory::SuspiciousUserAgent, "DirBuster", true, MatchTarget::UserAgent});
}

bool PayloadSignatureMatcher::contains_substring(std::string_view haystack, std::string_view needle, bool case_insensitive) noexcept {
    if (needle.empty() || haystack.size() < needle.size()) {
        return false;
    }

    if (!case_insensitive) {
        return haystack.find(needle) != std::string_view::npos;
    }

    auto it = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
                          [](char ch1, char ch2) {
                              return std::tolower(static_cast<unsigned char>(ch1)) ==
                                     std::tolower(static_cast<unsigned char>(ch2));
                          });
    return it != haystack.end();
}

bool PayloadSignatureMatcher::match(const ParsedPacket& packet,
                                    const L7Metadata& l7_meta,
                                    const uint8_t* payload,
                                    size_t payload_len,
                                    uint64_t timestamp_us,
                                    SecurityAlert& out_alert) const {
    size_t inspect_len = std::min(payload_len, config_.max_inspect_payload_bytes);
    std::string_view payload_view{};
    if (payload != nullptr && inspect_len > 0) {
        payload_view = std::string_view(reinterpret_cast<const char*>(payload), inspect_len);
    }

    std::string_view uri_view{};
    std::string_view host_view = l7_meta.hostname;
    std::string_view user_agent_view{};

    if (l7_meta.protocol == AppProtocol::HTTP) {
        uri_view = l7_meta.http.uri;
        if (host_view.empty()) {
            host_view = l7_meta.http.host;
        }
    } else if (l7_meta.protocol == AppProtocol::TLS) {
        if (host_view.empty()) {
            host_view = l7_meta.tls.sni;
        }
    } else if (l7_meta.protocol == AppProtocol::DNS) {
        if (host_view.empty()) {
            host_view = l7_meta.dns.qname;
        }
    }

    for (const auto& sig : signatures_) {
        bool matched = false;
        std::string_view match_source{};

        switch (sig.target) {
            case MatchTarget::Uri:
                if (!uri_view.empty() && contains_substring(uri_view, sig.pattern, sig.case_insensitive)) {
                    matched = true;
                    match_source = uri_view;
                } else if (!payload_view.empty() && contains_substring(payload_view, sig.pattern, sig.case_insensitive)) {
                    matched = true;
                    match_source = payload_view;
                }
                break;

            case MatchTarget::Host:
                if (!host_view.empty() && contains_substring(host_view, sig.pattern, sig.case_insensitive)) {
                    matched = true;
                    match_source = host_view;
                }
                break;

            case MatchTarget::UserAgent:
                if (!user_agent_view.empty() && contains_substring(user_agent_view, sig.pattern, sig.case_insensitive)) {
                    matched = true;
                    match_source = user_agent_view;
                } else if (!payload_view.empty() && contains_substring(payload_view, sig.pattern, sig.case_insensitive)) {
                    matched = true;
                    match_source = payload_view;
                }
                break;

            case MatchTarget::AnyPayload:
            default:
                if (!payload_view.empty() && contains_substring(payload_view, sig.pattern, sig.case_insensitive)) {
                    matched = true;
                    match_source = payload_view;
                } else if (!uri_view.empty() && contains_substring(uri_view, sig.pattern, sig.case_insensitive)) {
                    matched = true;
                    match_source = uri_view;
                } else if (!host_view.empty() && contains_substring(host_view, sig.pattern, sig.case_insensitive)) {
                    matched = true;
                    match_source = host_view;
                }
                break;
        }

        if (matched) {
            IPAddress src_ip = packet.is_ipv4() ? IPAddress(packet.ipv4.src_ip) : (packet.is_ipv6() ? IPAddress(packet.ipv6.src_ip) : IPAddress{});
            IPAddress dst_ip = packet.is_ipv4() ? IPAddress(packet.ipv4.dst_ip) : (packet.is_ipv6() ? IPAddress(packet.ipv6.dst_ip) : IPAddress{});
            uint16_t src_port = packet.is_tcp() ? packet.tcp.src_port : (packet.is_udp() ? packet.udp.src_port : 0);
            uint16_t dst_port = packet.is_tcp() ? packet.tcp.dst_port : (packet.is_udp() ? packet.udp.dst_port : 0);

            out_alert.timestamp_us = timestamp_us;
            out_alert.severity = sig.severity;
            out_alert.category = sig.category;
            out_alert.signature_name = sig.name;
            out_alert.description = "Matched payload threat signature: " + sig.name;
            out_alert.src_ip = src_ip;
            out_alert.dst_ip = dst_ip;
            out_alert.src_port = src_port;
            out_alert.dst_port = dst_port;
            out_alert.transport = packet.l4_type;
            out_alert.app_protocol = l7_meta.protocol;
            out_alert.trigger_reason = "Signature match pattern='" + sig.pattern + "' in target=" + (sig.target == MatchTarget::UserAgent ? "User-Agent" : (sig.target == MatchTarget::Uri ? "URI" : "Payload"));

            size_t snippet_len = std::min<size_t>(match_source.size(), 128);
            out_alert.matched_snippet = std::string(match_source.substr(0, snippet_len));
            return true;
        }
    }

    return false;
}

} // namespace dpi
