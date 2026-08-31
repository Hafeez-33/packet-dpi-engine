#include "dpi/flow/ip_address.h"
#include <cstring>

namespace dpi {

bool IPAddress::operator==(const IPAddress& other) const noexcept {
    if (version_ != other.version_) return false;
    if (version_ == Version::IPv4) {
        return v4_ == other.v4_;
    }
    if (version_ == Version::IPv6) {
        return v6_ == other.v6_;
    }
    return true;
}

bool IPAddress::operator<(const IPAddress& other) const noexcept {
    if (version_ != other.version_) {
        return static_cast<uint8_t>(version_) < static_cast<uint8_t>(other.version_);
    }
    if (version_ == Version::IPv4) {
        return v4_.to_u32() < other.v4_.to_u32();
    }
    if (version_ == Version::IPv6) {
        return v6_.bytes < other.v6_.bytes;
    }
    return false;
}

std::string IPAddress::to_string() const {
    if (version_ == Version::IPv4) {
        return v4_.to_string();
    }
    if (version_ == Version::IPv6) {
        return v6_.to_string();
    }
    return "0.0.0.0";
}

} // namespace dpi
