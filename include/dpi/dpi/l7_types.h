#ifndef DPI_DPI_L7_TYPES_H
#define DPI_DPI_L7_TYPES_H

#include <cstdint>
#include <string>
#include <string_view>

namespace dpi {

/**
 * @brief High-level application protocol classification taxonomy.
 */
enum class AppProtocol : uint8_t {
    Unknown = 0,
    TLS,
    HTTP,
    DNS
};

/**
 * @brief Converts AppProtocol enum to a human-readable string view.
 */
std::string_view app_protocol_to_string(AppProtocol proto) noexcept;

/**
 * @brief Extracted metadata from TLS handshake records.
 */
struct TlsMetadata {
    uint16_t legacy_version{0};     // Record layer version (e.g. 0x0303)
    uint16_t client_version{0};     // Handshake ClientHello version
    std::string sni{};              // Extracted Server Name Indication
    bool has_sni{false};
};

/**
 * @brief Extracted metadata from HTTP/1.x textual requests.
 */
struct HttpMetadata {
    std::string method{};           // GET, POST, HEAD, PUT, DELETE, etc.
    std::string uri{};              // Request URI path
    std::string version{};          // HTTP/1.0, HTTP/1.1
    std::string host{};             // Extracted Host header
    bool has_host{false};
};

/**
 * @brief Extracted metadata from DNS wire-format packets.
 */
struct DnsMetadata {
    uint16_t transaction_id{0};
    uint16_t flags{0};
    uint16_t qtype{0};              // 1 = A, 28 = AAAA, 5 = CNAME, etc.
    uint16_t qclass{0};             // 1 = IN
    std::string qname{};            // Normalized domain name (e.g. "www.google.com")
};

/**
 * @brief Aggregated Layer-7 inspection metadata stored on flow records.
 */
struct L7Metadata {
    AppProtocol protocol{AppProtocol::Unknown};
    std::string hostname{};         // Normalized domain: SNI (TLS), Host (HTTP), QNAME (DNS)
    std::string details{};          // Detailed summary (e.g. "GET /index.html HTTP/1.1")
    bool is_classified{false};
    float confidence{1.0f};

    TlsMetadata tls{};
    HttpMetadata http{};
    DnsMetadata dns{};
};

/**
 * @brief Result returned from DPI inspection operations.
 */
struct DpiResult {
    bool matched{false};
    L7Metadata metadata{};
};

} // namespace dpi

#endif // DPI_DPI_L7_TYPES_H
