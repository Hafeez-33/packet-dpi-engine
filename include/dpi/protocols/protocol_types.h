#ifndef DPI_PROTOCOL_TYPES_H
#define DPI_PROTOCOL_TYPES_H

#include <array>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>

namespace dpi {

// Protocol parsing status and error codes
enum class ProtocolErrorCode {
    Success = 0,
    EmptyPacket,
    TruncatedEthernet,
    UnsupportedEtherType,
    TruncatedIPv4,
    InvalidIPv4Version,
    InvalidIPv4IHL,
    IPv4TotalLengthTooSmall,
    IPv4PacketTooShortForTotalLength,
    IPv4FragmentedNonInitial,
    TruncatedIPv6,
    InvalidIPv6Version,
    IPv6PacketTooShortForPayload,
    UnsupportedIPv6ExtensionHeader,
    UnsupportedL3Protocol,
    TruncatedTCP,
    InvalidTcpDataOffset,
    TcpSegmentTooShortForDataOffset,
    TruncatedUDP,
    InvalidUdpLength,
    UdpPacketTooShortForLength,
    UnsupportedL4Protocol
};

// Converts ProtocolErrorCode to a human-readable string view
std::string_view protocol_error_to_string(ProtocolErrorCode code) noexcept;

// Common standard EtherType values (host byte order)
namespace ethertype {
    constexpr uint16_t IPV4 = 0x0800;
    constexpr uint16_t ARP  = 0x0806;
    constexpr uint16_t VLAN = 0x8100;
    constexpr uint16_t IPV6 = 0x86DD;
}

// Common standard IP Protocol numbers (RFC 790 / IANA)
namespace ipproto {
    constexpr uint8_t ICMP      = 1;
    constexpr uint8_t TCP       = 6;
    constexpr uint8_t UDP       = 17;
    constexpr uint8_t IPV6_ICMP = 58;
}

// Layer-3 Protocol Classifier
enum class L3Type {
    None = 0,
    IPv4,
    IPv6,
    Unsupported
};

// Layer-4 Protocol Classifier
enum class L4Type {
    None = 0,
    TCP,
    UDP,
    IPv4Fragment,
    Other,
    Unsupported
};

// 6-byte Ethernet MAC Address
struct MacAddress {
    std::array<uint8_t, 6> bytes{0, 0, 0, 0, 0, 0};

    bool operator==(const MacAddress& other) const noexcept {
        return bytes == other.bytes;
    }

    bool operator!=(const MacAddress& other) const noexcept {
        return !(*this == other);
    }

    std::string to_string() const {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (size_t i = 0; i < bytes.size(); ++i) {
            if (i > 0) oss << ":";
            oss << std::setw(2) << static_cast<int>(bytes[i]);
        }
        return oss.str();
    }
};

// 4-byte IPv4 Address (network order bytes stored with host integer representation)
struct IPv4Address {
    std::array<uint8_t, 4> bytes{0, 0, 0, 0};

    IPv4Address() = default;
    constexpr IPv4Address(uint8_t a, uint8_t b, uint8_t c, uint8_t d) noexcept
        : bytes{a, b, c, d} {}

    explicit constexpr IPv4Address(uint32_t host_order_u32) noexcept
        : bytes{
            static_cast<uint8_t>((host_order_u32 >> 24) & 0xFF),
            static_cast<uint8_t>((host_order_u32 >> 16) & 0xFF),
            static_cast<uint8_t>((host_order_u32 >> 8) & 0xFF),
            static_cast<uint8_t>(host_order_u32 & 0xFF)
        } {}

    uint32_t to_u32() const noexcept {
        return (static_cast<uint32_t>(bytes[0]) << 24) |
               (static_cast<uint32_t>(bytes[1]) << 16) |
               (static_cast<uint32_t>(bytes[2]) << 8)  |
               static_cast<uint32_t>(bytes[3]);
    }

    bool operator==(const IPv4Address& other) const noexcept {
        return bytes == other.bytes;
    }

    bool operator!=(const IPv4Address& other) const noexcept {
        return !(*this == other);
    }

    std::string to_string() const {
        std::ostringstream oss;
        oss << static_cast<int>(bytes[0]) << "."
            << static_cast<int>(bytes[1]) << "."
            << static_cast<int>(bytes[2]) << "."
            << static_cast<int>(bytes[3]);
        return oss.str();
    }
};

// 16-byte IPv6 Address
struct IPv6Address {
    std::array<uint8_t, 16> bytes{0};

    IPv6Address() = default;
    explicit constexpr IPv6Address(const std::array<uint8_t, 16>& b) noexcept : bytes(b) {}

    bool operator==(const IPv6Address& other) const noexcept {
        return bytes == other.bytes;
    }

    bool operator!=(const IPv6Address& other) const noexcept {
        return !(*this == other);
    }

    std::string to_string() const {
        std::ostringstream oss;
        oss << std::hex;
        for (size_t i = 0; i < 16; i += 2) {
            if (i > 0) oss << ":";
            uint16_t group = (static_cast<uint16_t>(bytes[i]) << 8) | bytes[i + 1];
            oss << group;
        }
        return oss.str();
    }
};

// Alignment-safe byte reading utilities from raw network stream
inline uint8_t read_u8(const uint8_t* ptr) noexcept {
    return *ptr;
}

inline uint16_t read_u16_be(const uint8_t* ptr) noexcept {
    return static_cast<uint16_t>((static_cast<uint16_t>(ptr[0]) << 8) |
                                  static_cast<uint16_t>(ptr[1]));
}

inline uint32_t read_u32_be(const uint8_t* ptr) noexcept {
    return (static_cast<uint32_t>(ptr[0]) << 24) |
           (static_cast<uint32_t>(ptr[1]) << 16) |
           (static_cast<uint32_t>(ptr[2]) << 8)  |
            static_cast<uint32_t>(ptr[3]);
}

} // namespace dpi

#endif // DPI_PROTOCOL_TYPES_H
