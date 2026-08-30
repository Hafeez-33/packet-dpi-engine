#ifndef DPI_DPI_DPI_ENGINE_H
#define DPI_DPI_DPI_ENGINE_H

#include "dpi/dpi/l7_types.h"
#include "dpi/protocols/parsed_packet.h"
#include <string_view>

namespace dpi {

/**
 * @brief Unified Layer-7 Deep Packet Inspection (DPI) and Application Classification Engine.
 * 
 * Performs safe, zero-copy protocol identification across TLS, HTTP/1.x, and DNS.
 */
class DpiEngine {
public:
    /**
     * @brief Inspects a transport payload stream and identifies the application protocol.
     * @param payload Transport payload or accumulated reassembly buffer
     * @param protocol Transport protocol (TCP=6, UDP=17)
     * @param src_port Source port (heuristic hint)
     * @param dst_port Destination port (heuristic hint)
     * @return DpiResult containing matched status and extracted L7 metadata
     */
    static DpiResult inspect(std::string_view payload,
                            uint8_t protocol,
                            uint16_t src_port = 0,
                            uint16_t dst_port = 0) noexcept;

    /**
     * @brief Inspects a decoded ParsedPacket directly.
     * @param packet The parsed packet
     * @return DpiResult containing matched status and extracted L7 metadata
     */
    static DpiResult inspect(const ParsedPacket& packet) noexcept;
};

} // namespace dpi

#endif // DPI_DPI_DPI_ENGINE_H
