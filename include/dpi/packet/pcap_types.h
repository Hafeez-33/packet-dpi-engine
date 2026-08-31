#ifndef DPI_PCAP_TYPES_H
#define DPI_PCAP_TYPES_H

#include <cstdint>
#include <string_view>
#include <vector>

namespace dpi {

// Classic PCAP Magic Numbers
namespace pcap_magic {
    constexpr uint32_t MICROSEC_NATIVE  = 0xa1b2c3d4;
    constexpr uint32_t MICROSEC_SWAPPED = 0xd4c3b2a1;
    constexpr uint32_t NANOSEC_NATIVE   = 0xa1b23c4d;
    constexpr uint32_t NANOSEC_SWAPPED  = 0x4d3cb2a1;
}

// Version requirement constants for classic PCAP format
namespace pcap_version {
    constexpr uint16_t MAJOR_REQUIRED = 2;
    constexpr uint16_t MINOR_REQUIRED = 4;
}

// Error codes for PCAP parsing operations
enum class PcapErrorCode {
    Success = 0,
    FileNotFound,
    StreamError,
    TruncatedGlobalHeader,
    InvalidMagicNumber,
    UnsupportedVersion,
    InvalidSnaplen,
    TruncatedPacketHeader,
    TruncatedPacketData,
    CorruptPacketLength,
    PacketExceedsMaxLimit,
    EndOfFile
};

// Convert PcapErrorCode to human-readable description
std::string_view pcap_error_to_string(PcapErrorCode code) noexcept;

// Classic PCAP Global Header (24 bytes on wire)
struct GlobalHeader {
    uint32_t magic_number{0};
    uint16_t version_major{0};
    uint16_t version_minor{0};
    int32_t  thiszone{0};
    uint32_t sigfigs{0};
    uint32_t snaplen{0};
    uint32_t network{0}; // Data link type (e.g. 1 = DLT_EN10MB)

    // Derived metadata
    bool is_byte_swapped{false};
    bool is_nanosecond_resolution{false};
};

// Classic PCAP Packet Header (16 bytes on wire)
struct PacketHeader {
    uint32_t ts_sec{0};
    uint32_t ts_usec{0}; // Microseconds or nanoseconds depending on GlobalHeader
    uint32_t incl_len{0}; // Captured payload size
    uint32_t orig_len{0}; // Original packet length on wire
};

// Complete packet record holding header and raw payload bytes
struct PacketRecord {
    PacketHeader header{};
    std::vector<uint8_t> payload{};
};

// Safe endian swapping utilities
inline uint16_t bswap16(uint16_t val) noexcept {
    return static_cast<uint16_t>((val << 8) | (val >> 8));
}

inline uint32_t bswap32(uint32_t val) noexcept {
    return ((val & 0x000000FFu) << 24) |
           ((val & 0x0000FF00u) << 8)  |
           ((val & 0x00FF0000u) >> 8)  |
           ((val & 0xFF000000u) >> 24);
}

} // namespace dpi

#endif // DPI_PCAP_TYPES_H
