#include "dpi/threat/entropy_calculator.h"
#include <array>
#include <cmath>

namespace dpi {

double EntropyCalculator::calculate_shannon_entropy(std::string_view input) noexcept {
    return calculate_shannon_entropy(reinterpret_cast<const uint8_t*>(input.data()), input.size());
}

double EntropyCalculator::calculate_shannon_entropy(const uint8_t* data, size_t length) noexcept {
    if (data == nullptr || length == 0) {
        return 0.0;
    }

    std::array<size_t, 256> counts{};
    for (size_t i = 0; i < length; ++i) {
        counts[data[i]]++;
    }

    double entropy = 0.0;
    double inv_len = 1.0 / static_cast<double>(length);

    for (size_t count : counts) {
        if (count > 0) {
            double p = static_cast<double>(count) * inv_len;
            entropy -= p * (std::log(p) / std::log(2.0)); // log2(p)
        }
    }

    return (entropy < 0.0) ? 0.0 : entropy;
}

} // namespace dpi
