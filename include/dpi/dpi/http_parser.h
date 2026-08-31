#ifndef DPI_DPI_HTTP_PARSER_H
#define DPI_DPI_HTTP_PARSER_H

#include "dpi/dpi/l7_types.h"
#include <string_view>

namespace dpi {

/**
 * @brief High-performance, zero-copy HTTP/1.x textual request and Host header parser.
 */
class HttpParser {
public:
    /**
     * @brief Parses an HTTP/1.x textual request stream and extracts Method, URI, Version, and Host.
     * @param payload Transport payload or accumulated reassembly buffer
     * @param out_meta Output metadata populated if an HTTP/1.x request is identified
     * @return True if a valid HTTP/1.x request was parsed, false otherwise
     */
    static bool parse_request(std::string_view payload, HttpMetadata& out_meta) noexcept;
};

} // namespace dpi

#endif // DPI_DPI_HTTP_PARSER_H
