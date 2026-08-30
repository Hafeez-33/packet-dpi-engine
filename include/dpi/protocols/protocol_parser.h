#ifndef DPI_PROTOCOLS_PROTOCOL_PARSER_H
#define DPI_PROTOCOLS_PROTOCOL_PARSER_H

#include "dpi/packet/pcap_types.h"
#include "dpi/protocols/parsed_packet.h"
#include <cstddef>
#include <cstdint>

namespace dpi {

/**
 * @brief High-performance, bounds-checked protocol parser for Ethernet, IPv4, IPv6, TCP, and UDP.
 * 
 * Slices headers safely using explicit endian-aware byte deserialization without struct casting.
 * Produces a canonical ParsedPacket structure containing layer metadata and zero-copy payload views.
 */
class ProtocolParser {
public:
    /**
     * @brief Parse a raw packet buffer from Layer 2 up through Layer 4.
     * @param data Pointer to raw packet byte buffer
     * @param length Number of bytes captured in buffer
     * @return ParsedPacket containing decoded protocol metadata or error code
     */
    static ParsedPacket parse(const uint8_t* data, size_t length) noexcept;

    /**
     * @brief Parse a PacketRecord produced by PcapReader.
     * @param record The PacketRecord from Stage 1 PCAP ingestion
     * @return ParsedPacket containing decoded protocol metadata or error code
     */
    static ParsedPacket parse(const PacketRecord& record) noexcept;

    /**
     * @brief Parse Ethernet II header (14 bytes).
     */
    static ProtocolErrorCode parse_ethernet(const uint8_t* data, size_t length,
                                            EthernetHeader& out_eth, size_t& consumed) noexcept;

    /**
     * @brief Parse IPv4 header including header length validation, fragmentation, and options.
     */
    static ProtocolErrorCode parse_ipv4(const uint8_t* data, size_t length,
                                        IPv4Header& out_ipv4, size_t& consumed) noexcept;

    /**
     * @brief Parse IPv6 base header (40 bytes).
     */
    static ProtocolErrorCode parse_ipv6(const uint8_t* data, size_t length,
                                        IPv6Header& out_ipv6, size_t& consumed) noexcept;

    /**
     * @brief Parse TCP header including flags, data offset, options, and payload boundaries.
     */
    static ProtocolErrorCode parse_tcp(const uint8_t* data, size_t length,
                                       TcpHeader& out_tcp, size_t& consumed) noexcept;

    /**
     * @brief Parse UDP header including length bounds checking and payload boundaries.
     */
    static ProtocolErrorCode parse_udp(const uint8_t* data, size_t length,
                                       UdpHeader& out_udp, size_t& consumed) noexcept;
};

} // namespace dpi

#endif // DPI_PROTOCOLS_PROTOCOL_PARSER_H
