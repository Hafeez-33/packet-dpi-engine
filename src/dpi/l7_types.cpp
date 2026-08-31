#include "dpi/dpi/l7_types.h"

namespace dpi {

std::string_view app_protocol_to_string(AppProtocol proto) noexcept {
    switch (proto) {
        case AppProtocol::TLS:
            return "TLS";
        case AppProtocol::HTTP:
            return "HTTP";
        case AppProtocol::DNS:
            return "DNS";
        case AppProtocol::Unknown:
        default:
            return "Unknown";
    }
}

} // namespace dpi
