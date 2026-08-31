#include "dpi/dpi/tls_parser.h"
#include "dpi/protocols/protocol_types.h"
#include <algorithm>
#include <cstdint>

namespace dpi {

bool TlsParser::parse_client_hello(std::string_view payload, TlsMetadata& out_meta) noexcept {
    const uint8_t* data = reinterpret_cast<const uint8_t*>(payload.data());
    size_t length = payload.size();

    // 1. Minimum TLS Record Header (5 bytes)
    if (length < 5) {
        return false;
    }

    // Content Type 0x16 = Handshake
    uint8_t content_type = data[0];
    if (content_type != 0x16) {
        return false;
    }

    // Record layer legacy version check (0x0300 through 0x0304)
    uint16_t record_version = read_u16_be(data + 1);
    if (record_version < 0x0300 || record_version > 0x0304) {
        return false;
    }

    out_meta.legacy_version = record_version;

    // Record length (2 bytes)
    uint16_t record_len = read_u16_be(data + 3);
    if (record_len == 0) {
        return false;
    }

    // 2. Minimum Handshake Header (4 bytes) at offset 5
    if (length < 5 + 4) {
        return false;
    }

    // Handshake Type 0x01 = ClientHello
    uint8_t handshake_type = data[5];
    if (handshake_type != 0x01) {
        return false;
    }

    // 3. ClientHello Body
    // Client Version (2 bytes) at offset 9
    if (length < 9 + 2 + 32 + 1) { // Up to session ID length
        return false;
    }

    out_meta.client_version = read_u16_be(data + 9);
    out_meta.has_sni = false;
    out_meta.sni.clear();

    // Skip Random (32 bytes) -> offset = 43
    size_t offset = 43;

    // Session ID length (1 byte)
    uint8_t session_id_len = data[offset];
    offset += 1 + session_id_len;

    // Cipher Suites length (2 bytes)
    if (offset + 2 > length) {
        return true; // Valid ClientHello so far
    }
    uint16_t cipher_suites_len = read_u16_be(data + offset);
    offset += 2 + cipher_suites_len;

    // Compression Methods length (1 byte)
    if (offset + 1 > length) {
        return true;
    }
    uint8_t comp_methods_len = data[offset];
    offset += 1 + comp_methods_len;

    // Extensions length (2 bytes)
    if (offset + 2 > length) {
        return true; // Valid ClientHello without extensions
    }
    uint16_t extensions_len = read_u16_be(data + offset);
    offset += 2;

    size_t extensions_end = std::min<size_t>(length, offset + extensions_len);

    // 4. Iterate over TLS Extensions
    while (offset + 4 <= extensions_end) {
        uint16_t ext_type = read_u16_be(data + offset);
        uint16_t ext_len = read_u16_be(data + offset + 2);
        offset += 4;

        if (offset + ext_len > extensions_end) {
            break;
        }

        // Extension 0x0000 = Server Name Indication (SNI)
        if (ext_type == 0x0000) {
            if (ext_len >= 2) {
                uint16_t server_name_list_len = read_u16_be(data + offset);
                size_t sni_offset = offset + 2;
                size_t sni_end = std::min<size_t>(offset + ext_len, sni_offset + server_name_list_len);

                while (sni_offset + 3 <= sni_end) {
                    uint8_t name_type = data[sni_offset];
                    uint16_t name_len = read_u16_be(data + sni_offset + 1);
                    sni_offset += 3;

                    if (sni_offset + name_len > sni_end) {
                        break;
                    }

                    // Name Type 0x00 = host_name
                    if (name_type == 0x00 && name_len > 0) {
                        out_meta.sni = std::string(reinterpret_cast<const char*>(data + sni_offset), name_len);
                        out_meta.has_sni = true;
                        return true;
                    }
                    sni_offset += name_len;
                }
            }
            break;
        }

        offset += ext_len;
    }

    return true;
}

} // namespace dpi
