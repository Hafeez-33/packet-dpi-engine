#ifndef DPI_THREAT_BOUNDED_ALERT_BUFFER_H
#define DPI_THREAT_BOUNDED_ALERT_BUFFER_H

#include "dpi/threat/threat_types.h"
#include <cstddef>
#include <cstdint>
#include <vector>

namespace dpi {

/**
 * @brief Thread-safe (or worker-local) bounded circular ring buffer for SecurityAlert events.
 * 
 * Enforces a strict maximum capacity. When capacity is exceeded, oldest alerts
 * are overwritten and dropped_count is incremented, guaranteeing bounded memory.
 */
class BoundedAlertBuffer {
public:
    explicit BoundedAlertBuffer(size_t capacity = 1000) noexcept
        : capacity_(capacity > 0 ? capacity : 1),
          buffer_(capacity > 0 ? capacity : 1) {}

    void push(SecurityAlert alert) {
        if (size_ < capacity_) {
            buffer_[head_] = std::move(alert);
            head_ = (head_ + 1) % capacity_;
            size_++;
        } else {
            // Buffer is full: overwrite oldest at tail_ and advance tail
            buffer_[tail_] = std::move(alert);
            tail_ = (tail_ + 1) % capacity_;
            head_ = tail_;
            dropped_count_++;
        }
        total_generated_count_++;
    }

    std::vector<SecurityAlert> get_snapshot() const {
        std::vector<SecurityAlert> result;
        result.reserve(size_);
        for (size_t i = 0; i < size_; ++i) {
            size_t idx = (tail_ + i) % capacity_;
            result.push_back(buffer_[idx]);
        }
        return result;
    }

    size_t size() const noexcept { return size_; }
    size_t capacity() const noexcept { return capacity_; }
    uint64_t dropped_count() const noexcept { return dropped_count_; }
    uint64_t total_generated_count() const noexcept { return total_generated_count_; }

    void clear() noexcept {
        head_ = 0;
        tail_ = 0;
        size_ = 0;
    }

private:
    size_t capacity_{1000};
    std::vector<SecurityAlert> buffer_{};
    size_t head_{0};
    size_t tail_{0};
    size_t size_{0};
    uint64_t dropped_count_{0};
    uint64_t total_generated_count_{0};
};

} // namespace dpi

#endif // DPI_THREAT_BOUNDED_ALERT_BUFFER_H
