#ifndef DPI_VERSION_H
#define DPI_VERSION_H

#include <string_view>

namespace dpi {

struct Version {
    static constexpr int MAJOR = 0;
    static constexpr int MINOR = 1;
    static constexpr int PATCH = 0;
    static constexpr std::string_view STRING = "0.1.0-dev";
};

std::string_view get_version_string() noexcept;

} // namespace dpi

#endif // DPI_VERSION_H
