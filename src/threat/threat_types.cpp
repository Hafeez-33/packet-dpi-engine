#include "dpi/threat/threat_types.h"
#include <algorithm>
#include <cctype>

namespace dpi {

std::string severity_to_string(AlertSeverity severity) {
    switch (severity) {
        case AlertSeverity::Critical: return "CRITICAL";
        case AlertSeverity::High:     return "HIGH";
        case AlertSeverity::Medium:   return "MEDIUM";
        case AlertSeverity::Low:      return "LOW";
        case AlertSeverity::Info:
        default:                      return "INFO";
    }
}

std::string category_to_string(ThreatCategory category) {
    switch (category) {
        case ThreatCategory::PortScan:            return "PORT_SCAN";
        case ThreatCategory::SynFlood:            return "SYN_FLOOD";
        case ThreatCategory::DnsTunneling:        return "DNS_TUNNELING";
        case ThreatCategory::DnsDgaAnomaly:       return "DNS_DGA_ANOMALY";
        case ThreatCategory::SqlInjection:        return "SQL_INJECTION";
        case ThreatCategory::DirectoryTraversal:  return "DIRECTORY_TRAVERSAL";
        case ThreatCategory::SuspiciousUserAgent: return "SUSPICIOUS_USER_AGENT";
        case ThreatCategory::MalformedTraffic:    return "MALFORMED_TRAFFIC";
        case ThreatCategory::CustomSignature:
        default:                                  return "CUSTOM_SIGNATURE";
    }
}

AlertSeverity string_to_severity(std::string_view str) noexcept {
    if (str == "CRITICAL" || str == "critical") return AlertSeverity::Critical;
    if (str == "HIGH"     || str == "high")     return AlertSeverity::High;
    if (str == "MEDIUM"   || str == "medium")   return AlertSeverity::Medium;
    if (str == "LOW"      || str == "low")      return AlertSeverity::Low;
    return AlertSeverity::Info;
}

ThreatCategory string_to_category(std::string_view str) noexcept {
    if (str == "PORT_SCAN"             || str == "port_scan")             return ThreatCategory::PortScan;
    if (str == "SYN_FLOOD"             || str == "syn_flood")             return ThreatCategory::SynFlood;
    if (str == "DNS_TUNNELING"         || str == "dns_tunneling")         return ThreatCategory::DnsTunneling;
    if (str == "DNS_DGA_ANOMALY"       || str == "dns_dga_anomaly")       return ThreatCategory::DnsDgaAnomaly;
    if (str == "SQL_INJECTION"         || str == "sql_injection")         return ThreatCategory::SqlInjection;
    if (str == "DIRECTORY_TRAVERSAL"  || str == "directory_traversal")  return ThreatCategory::DirectoryTraversal;
    if (str == "SUSPICIOUS_USER_AGENT" || str == "suspicious_user_agent") return ThreatCategory::SuspiciousUserAgent;
    if (str == "MALFORMED_TRAFFIC"    || str == "malformed_traffic")    return ThreatCategory::MalformedTraffic;
    return ThreatCategory::CustomSignature;
}

} // namespace dpi
