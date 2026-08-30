#include "dpi/protocols/protocol_types.h"

namespace dpi {

std::string_view protocol_error_to_string(ProtocolErrorCode code) noexcept {
    switch (code) {
        case ProtocolErrorCode::Success:
            return "Success";
        case ProtocolErrorCode::EmptyPacket:
            return "Empty packet data";
        case ProtocolErrorCode::TruncatedEthernet:
            return "Truncated Ethernet frame (less than 14 bytes)";
        case ProtocolErrorCode::UnsupportedEtherType:
            return "Unsupported EtherType";
        case ProtocolErrorCode::TruncatedIPv4:
            return "Truncated IPv4 header";
        case ProtocolErrorCode::InvalidIPv4Version:
            return "Invalid IPv4 version (expected 4)";
        case ProtocolErrorCode::InvalidIPv4IHL:
            return "Invalid IPv4 IHL (less than 5)";
        case ProtocolErrorCode::IPv4TotalLengthTooSmall:
            return "IPv4 total length is smaller than header length";
        case ProtocolErrorCode::IPv4PacketTooShortForTotalLength:
            return "Packet buffer smaller than IPv4 total length";
        case ProtocolErrorCode::IPv4FragmentedNonInitial:
            return "IPv4 fragmented non-initial segment (L4 header not present)";
        case ProtocolErrorCode::TruncatedIPv6:
            return "Truncated IPv6 header (less than 40 bytes)";
        case ProtocolErrorCode::InvalidIPv6Version:
            return "Invalid IPv6 version (expected 6)";
        case ProtocolErrorCode::IPv6PacketTooShortForPayload:
            return "Packet buffer smaller than IPv6 payload length specification";
        case ProtocolErrorCode::UnsupportedIPv6ExtensionHeader:
            return "Unsupported IPv6 extension header";
        case ProtocolErrorCode::UnsupportedL3Protocol:
            return "Unsupported L3 protocol";
        case ProtocolErrorCode::TruncatedTCP:
            return "Truncated TCP header (less than 20 bytes)";
        case ProtocolErrorCode::InvalidTcpDataOffset:
            return "Invalid TCP data offset (less than 5 words)";
        case ProtocolErrorCode::TcpSegmentTooShortForDataOffset:
            return "TCP segment shorter than data offset specification";
        case ProtocolErrorCode::TruncatedUDP:
            return "Truncated UDP header (less than 8 bytes)";
        case ProtocolErrorCode::InvalidUdpLength:
            return "Invalid UDP length field (less than 8 bytes)";
        case ProtocolErrorCode::UdpPacketTooShortForLength:
            return "Packet buffer smaller than UDP length field";
        case ProtocolErrorCode::UnsupportedL4Protocol:
            return "Unsupported L4 protocol";
        default:
            return "Unknown protocol error";
    }
}

} // namespace dpi
