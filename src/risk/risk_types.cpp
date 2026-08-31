#include "dpi/risk/risk_types.h"
#include <algorithm>
#include <cctype>

namespace dpi {

std::string_view risk_level_to_string(RiskLevel level) noexcept {
    switch (level) {
        case RiskLevel::None:     return "NONE";
        case RiskLevel::Low:      return "LOW";
        case RiskLevel::Medium:   return "MEDIUM";
        case RiskLevel::High:     return "HIGH";
        case RiskLevel::Critical: return "CRITICAL";
        default:                  return "NONE";
    }
}

RiskLevel string_to_risk_level(std::string_view str) noexcept {
    std::string upper;
    upper.reserve(str.size());
    for (char c : str) {
        upper.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    }

    if (upper == "CRITICAL") return RiskLevel::Critical;
    if (upper == "HIGH")     return RiskLevel::High;
    if (upper == "MEDIUM")   return RiskLevel::Medium;
    if (upper == "LOW")      return RiskLevel::Low;
    return RiskLevel::None;
}

} // namespace dpi
