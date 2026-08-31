#ifndef DPI_DPI_TLS_PARSER_H
#define DPI_DPI_TLS_PARSER_H

#include "dpi/dpi/l7_types.h"
#include <string_view>

namespace dpi {

/**
 * @brief High-performance, bounds-checked TLS 1.2 and 1.3 ClientHello and SNI parser.
 */
class TlsParser {
public:
    /**
     * @brief Parses a TLS record and extracts ClientHello metadata including SNI.
     * @param payload Transport payload or accumulated reassembly buffer
     * @param out_meta Output metadata populated if TLS ClientHello is detected
     * @return True if a valid TLS ClientHello was identified, false otherwise
     */
    static bool parse_client_hello(std::string_view payload, TlsMetadata& out_meta) noexcept;
};

} // namespace dpi

#endif // DPI_DPI_TLS_PARSER_H
