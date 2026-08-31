#ifndef DPI_FLOW_IP_ADDRESS_H
#define DPI_FLOW_IP_ADDRESS_H

#include "dpi/protocols/protocol_types.h"
#include <cstdint>
#include <string>

namespace dpi {

/**
 * @brief Unified IPv4 / IPv6 network address wrapper with strict deterministic ordering.
 */
class IPAddress {
public:
    enum class Version : uint8_t {
        None = 0,
        IPv4 = 4,
        IPv6 = 6
    };

    IPAddress() noexcept = default;
    explicit IPAddress(const IPv4Address& v4) noexcept : version_(Version::IPv4), v4_(v4) {}
    explicit IPAddress(const IPv6Address& v6) noexcept : version_(Version::IPv6), v6_(v6) {}

    Version version() const noexcept { return version_; }
    bool is_v4() const noexcept { return version_ == Version::IPv4; }
    bool is_v6() const noexcept { return version_ == Version::IPv6; }
    bool is_valid() const noexcept { return version_ != Version::None; }

    const IPv4Address& v4() const noexcept { return v4_; }
    const IPv6Address& v6() const noexcept { return v6_; }

    bool operator==(const IPAddress& other) const noexcept;
    bool operator!=(const IPAddress& other) const noexcept { return !(*this == other); }
    bool operator<(const IPAddress& other) const noexcept;

    std::string to_string() const;

private:
    Version version_{Version::None};
    IPv4Address v4_{};
    IPv6Address v6_{};
};

struct IPAddressHasher {
    size_t operator()(const IPAddress& ip) const noexcept {
        if (ip.is_v4()) {
            return std::hash<uint32_t>{}(ip.v4().to_u32());
        }
        if (ip.is_v6()) {
            size_t h = 0x811c9dc5;
            for (uint8_t b : ip.v6().bytes) {
                h ^= static_cast<size_t>(b);
                h *= 0x01000193;
            }
            return h;
        }
        return 0;
    }
};

} // namespace dpi

namespace std {
template <>
struct hash<dpi::IPAddress> {
    size_t operator()(const dpi::IPAddress& ip) const noexcept {
        return dpi::IPAddressHasher{}(ip);
    }
};
} // namespace std

#endif // DPI_FLOW_IP_ADDRESS_H
