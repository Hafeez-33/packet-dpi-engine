#include "dpi/version.h"

namespace dpi {

std::string_view get_version_string() noexcept {
    return Version::STRING;
}

} // namespace dpi
