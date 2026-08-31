#include "dpi/pipeline/flow_router.h"
#include "dpi/protocols/protocol_types.h"
#include <algorithm>

namespace dpi {

bool FlowRouter::extract_flow_key(const uint8_t* data, size_t length, FlowKey& out_key) noexcept {
    if (data == nullptr || length < 14) {
        return false;
    }

    // 1. Ethernet Header (14 bytes minimum)
    uint16_t ethertype = read_u16_be(data + 12);
    size_t offset = 14;

    // Handle 802.1Q VLAN Tagging (4 bytes)
    if (ethertype == ethertype::VLAN) {
        if (length < 18) {
            return false;
        }
        ethertype = read_u16_be(data + 16);
        offset = 18;
    }

    // 2. IPv4
    if (ethertype == ethertype::IPV4) {
        if (length < offset + 20) {
            return false;
        }

        uint8_t ver_ihl = data[offset];
        if ((ver_ihl >> 4) != 4) {
            return false;
        }

        size_t ihl_bytes = (ver_ihl & 0x0F) * 4;
        if (ihl_bytes < 20 || length < offset + ihl_bytes) {
            return false;
        }

        // Check for non-initial fragmentation
        uint16_t flags_frag = read_u16_be(data + offset + 6);
        uint16_t frag_offset = flags_frag & 0x1FFF;
        if (frag_offset != 0) {
            return false; // Non-initial fragments cannot route via L4 ports
        }

        uint8_t proto = data[offset + 9];
        uint32_t src_ip = read_u32_be(data + offset + 12);
        uint32_t dst_ip = read_u32_be(data + offset + 16);

        offset += ihl_bytes;
        uint16_t src_port = 0;
        uint16_t dst_port = 0;

        if (proto == ipproto::TCP || proto == ipproto::UDP) {
            if (length < offset + 4) {
                return false;
            }
            src_port = read_u16_be(data + offset);
            dst_port = read_u16_be(data + offset + 2);
        }

        auto [key, dir] = FlowKey::create(IPAddress(IPv4Address(src_ip)), src_port,
                                          IPAddress(IPv4Address(dst_ip)), dst_port,
                                          proto);
        out_key = key;
        return true;
    }

    // 3. IPv6
    if (ethertype == ethertype::IPV6) {
        if (length < offset + 40) {
            return false;
        }

        if ((data[offset] >> 4) != 6) {
            return false;
        }

        uint8_t next_header = data[offset + 6];
        std::array<uint8_t, 16> src_ip{}, dst_ip{};
        std::copy(data + offset + 8, data + offset + 24, src_ip.begin());
        std::copy(data + offset + 24, data + offset + 40, dst_ip.begin());

        offset += 40;
        uint16_t src_port = 0;
        uint16_t dst_port = 0;

        if (next_header == ipproto::TCP || next_header == ipproto::UDP) {
            if (length < offset + 4) {
                return false;
            }
            src_port = read_u16_be(data + offset);
            dst_port = read_u16_be(data + offset + 2);
        }

        auto [key, dir] = FlowKey::create(IPAddress(IPv6Address(src_ip)), src_port,
                                          IPAddress(IPv6Address(dst_ip)), dst_port,
                                          next_header);
        out_key = key;
        return true;
    }

    return false;
}

} // namespace dpi
