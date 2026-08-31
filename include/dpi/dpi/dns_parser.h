#ifndef DPI_DPI_DNS_PARSER_H
#define DPI_DPI_DNS_PARSER_H

#include "dpi/dpi/l7_types.h"
#include <string_view>

namespace dpi {

/**
 * @brief Cycle-safe, bounds-checked DNS wire-format query and QNAME parser.
 */
class DnsParser {
public:
    /**
     * @brief Parses a DNS packet payload and extracts Question section metadata (QNAME, QTYPE).
     * @param payload UDP transport payload
     * @param out_meta Output metadata populated if a valid DNS packet is identified
     * @return True if a valid DNS packet with a readable question was parsed, false otherwise
     */
    static bool parse_query(std::string_view payload, DnsMetadata& out_meta) noexcept;
};

} // namespace dpi

#endif // DPI_DPI_DNS_PARSER_H
