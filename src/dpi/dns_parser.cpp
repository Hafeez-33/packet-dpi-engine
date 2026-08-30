#include "dpi/dpi/dns_parser.h"
#include "dpi/protocols/protocol_types.h"
#include <cstdint>
#include <vector>

namespace dpi {

bool DnsParser::parse_query(std::string_view payload, DnsMetadata& out_meta) noexcept {
    const uint8_t* data = reinterpret_cast<const uint8_t*>(payload.data());
    size_t length = payload.size();

    // 1. DNS Header is 12 bytes minimum
    if (length < 12) {
        return false;
    }

    out_meta.transaction_id = read_u16_be(data);
    out_meta.flags = read_u16_be(data + 2);
    uint16_t qdcount = read_u16_be(data + 4);

    // Require at least one question
    if (qdcount == 0) {
        return false;
    }

    // 2. Parse first Question (QNAME)
    size_t curr = 12;
    bool jumped = false;
    size_t next_field_offset = 0;
    size_t jump_count = 0;
    constexpr size_t MAX_JUMPS = 5;

    // Visited bitset to detect cyclic compression pointer loops
    std::vector<bool> visited(length, false);
    std::string qname;

    while (true) {
        if (curr >= length) {
            return false; // Truncated
        }

        if (visited[curr]) {
            return false; // Pointer cycle detected!
        }
        visited[curr] = true;

        uint8_t len_byte = data[curr];

        // Zero byte marks the end of QNAME
        if (len_byte == 0) {
            if (!jumped) {
                next_field_offset = curr + 1;
            }
            break;
        }

        // Check for DNS Compression Pointer (two high bits set: 0xC0)
        if ((len_byte & 0xC0) == 0xC0) {
            if (curr + 1 >= length) {
                return false;
            }
            if (++jump_count > MAX_JUMPS) {
                return false; // Excessive pointer jumps
            }

            uint16_t ptr_offset = static_cast<uint16_t>(((len_byte & 0x3F) << 8) | data[curr + 1]);
            if (ptr_offset >= length) {
                return false; // Out-of-bounds compression pointer
            }

            if (!jumped) {
                next_field_offset = curr + 2;
                jumped = true;
            }

            curr = ptr_offset;
            continue;
        }

        // Direct label: len_byte <= 63
        if (len_byte > 63) {
            return false; // Invalid label length
        }

        size_t label_len = len_byte;
        curr += 1;

        if (curr + label_len > length) {
            return false; // Truncated label data
        }

        if (!qname.empty()) {
            qname.push_back('.');
        }
        qname.append(reinterpret_cast<const char*>(data + curr), label_len);

        curr += label_len;
    }

    out_meta.qname = qname;

    // 3. Extract QTYPE and QCLASS if present
    if (next_field_offset > 0 && next_field_offset + 4 <= length) {
        out_meta.qtype = read_u16_be(data + next_field_offset);
        out_meta.qclass = read_u16_be(data + next_field_offset + 2);
    } else {
        out_meta.qtype = 0;
        out_meta.qclass = 0;
    }

    return !qname.empty();
}

} // namespace dpi
