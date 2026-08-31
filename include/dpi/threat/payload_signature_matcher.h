#ifndef DPI_THREAT_PAYLOAD_SIGNATURE_MATCHER_H
#define DPI_THREAT_PAYLOAD_SIGNATURE_MATCHER_H

#include "dpi/dpi/l7_types.h"
#include "dpi/protocols/protocol_types.h"
#include "dpi/threat/threat_config.h"
#include "dpi/threat/threat_types.h"
#include <string>
#include <string_view>
#include <vector>

namespace dpi {

enum class MatchTarget : uint8_t {
    AnyPayload,
    Uri,
    Host,
    UserAgent
};

struct PayloadSignature {
    uint32_t id{0};
    std::string name{};
    AlertSeverity severity{AlertSeverity::High};
    ThreatCategory category{ThreatCategory::CustomSignature};
    std::string pattern{};
    bool case_insensitive{true};
    MatchTarget target{MatchTarget::AnyPayload};
};

/**
 * @brief Bounded multi-pattern substring scanner for L7 payload threat signatures.
 */
class PayloadSignatureMatcher {
public:
    explicit PayloadSignatureMatcher(const SignatureConfig& config = {}) noexcept;

    /**
     * @brief Adds a bounded signature rule. Returns false if capacity or length is exceeded.
     */
    bool add_signature(PayloadSignature sig);

    /**
     * @brief Populates standard built-in attack signatures (SQLi, Traversal, Scanner UAs).
     */
    void load_default_signatures();

    /**
     * @brief Evaluates packet payload and L7 metadata against all loaded signatures.
     * @return true if a signature matched.
     */
    bool match(const ParsedPacket& packet,
               const L7Metadata& l7_meta,
               const uint8_t* payload,
               size_t payload_len,
               uint64_t timestamp_us,
               SecurityAlert& out_alert) const;

    size_t size() const noexcept { return signatures_.size(); }
    void clear() noexcept { signatures_.clear(); }

private:
    static bool contains_substring(std::string_view haystack, std::string_view needle, bool case_insensitive) noexcept;

    SignatureConfig config_;
    std::vector<PayloadSignature> signatures_{};
};

} // namespace dpi

#endif // DPI_THREAT_PAYLOAD_SIGNATURE_MATCHER_H
