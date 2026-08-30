#ifndef DPI_PIPELINE_FLOW_ROUTER_H
#define DPI_PIPELINE_FLOW_ROUTER_H

#include "dpi/flow/flow_key.h"
#include <cstddef>
#include <cstdint>

namespace dpi {

/**
 * @brief Fast, allocation-free routing parser for producer-side flow affinity determination.
 * 
 * Performs minimal bounds-checked parsing to extract the canonical FlowKey without
 * executing full protocol parsing or creating deep copies.
 */
class FlowRouter {
public:
    /**
     * @brief Extracts the canonical FlowKey from raw packet wire bytes.
     * @param data Pointer to raw packet bytes
     * @param length Total length of raw packet
     * @param out_key Output destination for the normalized FlowKey
     * @return True if a valid IP/transport FlowKey was extracted, false otherwise
     */
    static bool extract_flow_key(const uint8_t* data, size_t length, FlowKey& out_key) noexcept;
};

} // namespace dpi

#endif // DPI_PIPELINE_FLOW_ROUTER_H
