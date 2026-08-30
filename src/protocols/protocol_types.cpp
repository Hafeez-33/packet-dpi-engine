#include "dpi/protocols/protocol_types.h"
#include <vector>

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

std::optional<IPv4Address> IPv4Address::from_string(std::string_view str) noexcept {
    if (str.empty()) return std::nullopt;
    std::array<uint8_t, 4> octets{0, 0, 0, 0};
    size_t start = 0;
    size_t octet_idx = 0;

    while (start < str.size() && octet_idx < 4) {
        size_t dot = str.find('.', start);
        if (dot == std::string_view::npos) dot = str.size();

        std::string_view part = str.substr(start, dot - start);
        if (part.empty() || part.size() > 3) return std::nullopt;

        unsigned int val = 0;
        for (char c : part) {
            if (c < '0' || c > '9') return std::nullopt;
            val = val * 10 + static_cast<unsigned int>(c - '0');
        }
        if (val > 255) return std::nullopt;

        octets[octet_idx++] = static_cast<uint8_t>(val);
        start = dot + 1;
    }

    if (octet_idx != 4 || start < str.size()) {
        return std::nullopt;
    }

    return IPv4Address(octets[0], octets[1], octets[2], octets[3]);
}

std::string IPv4Address::to_string() const {
    std::ostringstream oss;
    oss << static_cast<int>(bytes[0]) << "."
        << static_cast<int>(bytes[1]) << "."
        << static_cast<int>(bytes[2]) << "."
        << static_cast<int>(bytes[3]);
    return oss.str();
}

std::optional<IPv6Address> IPv6Address::from_string(std::string_view str) noexcept {
    if (str.empty()) return std::nullopt;
    std::array<uint16_t, 8> words{0};
    size_t double_colon_pos = str.find("::");

    if (double_colon_pos != std::string_view::npos) {
        // Double colon expansion
        std::string_view left = str.substr(0, double_colon_pos);
        std::string_view right = str.substr(double_colon_pos + 2);

        std::vector<uint16_t> left_words, right_words;
        auto parse_parts = [](std::string_view s, std::vector<uint16_t>& out) -> bool {
            if (s.empty()) return true;
            size_t start = 0;
            while (start < s.size()) {
                size_t colon = s.find(':', start);
                if (colon == std::string_view::npos) colon = s.size();
                std::string_view token = s.substr(start, colon - start);
                if (token.empty() || token.size() > 4) return false;
                unsigned int val = 0;
                for (char c : token) {
                    val <<= 4;
                    if (c >= '0' && c <= '9') val |= (c - '0');
                    else if (c >= 'a' && c <= 'f') val |= (c - 'a' + 10);
                    else if (c >= 'A' && c <= 'F') val |= (c - 'A' + 10);
                    else return false;
                }
                out.push_back(static_cast<uint16_t>(val));
                start = colon + 1;
            }
            return true;
        };

        if (!parse_parts(left, left_words) || !parse_parts(right, right_words)) {
            return std::nullopt;
        }

        if (left_words.size() + right_words.size() > 7) {
            return std::nullopt;
        }

        size_t idx = 0;
        for (uint16_t w : left_words) words[idx++] = w;
        size_t zeros = 8 - (left_words.size() + right_words.size());
        idx += zeros;
        for (uint16_t w : right_words) words[idx++] = w;
    } else {
        // Exactly 8 groups
        size_t start = 0;
        size_t word_idx = 0;
        while (start < str.size() && word_idx < 8) {
            size_t colon = str.find(':', start);
            if (colon == std::string_view::npos) colon = str.size();
            std::string_view token = str.substr(start, colon - start);
            if (token.empty() || token.size() > 4) return std::nullopt;
            unsigned int val = 0;
            for (char c : token) {
                val <<= 4;
                if (c >= '0' && c <= '9') val |= (c - '0');
                else if (c >= 'a' && c <= 'f') val |= (c - 'a' + 10);
                else if (c >= 'A' && c <= 'F') val |= (c - 'A' + 10);
                else return std::nullopt;
            }
            words[word_idx++] = static_cast<uint16_t>(val);
            start = colon + 1;
        }
        if (word_idx != 8 || start < str.size()) {
            return std::nullopt;
        }
    }

    std::array<uint8_t, 16> bytes{0};
    for (size_t i = 0; i < 8; ++i) {
        bytes[i * 2] = static_cast<uint8_t>((words[i] >> 8) & 0xFF);
        bytes[i * 2 + 1] = static_cast<uint8_t>(words[i] & 0xFF);
    }
    return IPv6Address(bytes);
}

std::string IPv6Address::to_string() const {
    std::ostringstream oss;
    oss << std::hex;
    for (size_t i = 0; i < 16; i += 2) {
        if (i > 0) oss << ":";
        uint16_t group = (static_cast<uint16_t>(bytes[i]) << 8) | bytes[i + 1];
        oss << group;
    }
    return oss.str();
}

} // namespace dpi

