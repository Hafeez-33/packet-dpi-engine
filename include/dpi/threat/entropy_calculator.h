#ifndef DPI_THREAT_ENTROPY_CALCULATOR_H
#define DPI_THREAT_ENTROPY_CALCULATOR_H

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace dpi {

/**
 * @brief High-performance base-2 Shannon Entropy calculator for byte spans and domain names.
 */
class EntropyCalculator {
public:
    /**
     * @brief Computes base-2 Shannon entropy in bits per character.
     * Range: [0.0, 8.0].
     */
    static double calculate_shannon_entropy(std::string_view input) noexcept;
    static double calculate_shannon_entropy(const uint8_t* data, size_t length) noexcept;
};

} // namespace dpi

#endif // DPI_THREAT_ENTROPY_CALCULATOR_H
