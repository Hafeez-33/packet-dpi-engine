#ifndef DPI_PIPELINE_BOUNDED_QUEUE_H
#define DPI_PIPELINE_BOUNDED_QUEUE_H

#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <queue>
#include <utility>

namespace dpi {

/**
 * @brief Thread-safe, bounded blocking FIFO queue supporting backpressure and graceful draining.
 */
template <typename T>
class BoundedQueue {
public:
    explicit BoundedQueue(size_t capacity) noexcept
        : capacity_(capacity > 0 ? capacity : 1024) {}

    ~BoundedQueue() {
        shutdown();
    }

    // Disable copy
    BoundedQueue(const BoundedQueue&) = delete;
    BoundedQueue& operator=(const BoundedQueue&) = delete;

    /**
     * @brief Pushes an item into the queue. Blocks the calling producer thread if the queue is full.
     * @param item Item to move into the queue
     * @return True if successfully enqueued, false if queue was shut down
     */
    bool push(T item) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_full_.wait(lock, [this] {
            return queue_.size() < capacity_ || shutdown_;
        });

        if (shutdown_) {
            return false;
        }

        queue_.push(std::move(item));
        not_empty_.notify_one();
        return true;
    }

    /**
     * @brief Pops an item from the queue. Blocks the consumer worker thread until an item is available.
     * @param item Output destination for the popped item
     * @return True if an item was popped, false if queue is shut down and empty
     */
    bool pop(T& item) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_empty_.wait(lock, [this] {
            return !queue_.empty() || shutdown_;
        });

        if (!queue_.empty()) {
            item = std::move(queue_.front());
            queue_.pop();
            not_full_.notify_one();
            return true;
        }

        // Shutdown signaled and all items drained
        return false;
    }

    /**
     * @brief Signals queue shutdown, waking all blocked producers and consumers.
     * 
     * Remaining queued items can still be popped until the queue is empty.
     */
    void shutdown() noexcept {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (shutdown_) return;
            shutdown_ = true;
        }
        not_empty_.notify_all();
        not_full_.notify_all();
    }

    size_t size() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

    bool empty() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }

    size_t capacity() const noexcept {
        return capacity_;
    }

private:
    size_t capacity_{1024};
    std::queue<T> queue_{};
    mutable std::mutex mutex_{};
    std::condition_variable not_empty_{};
    std::condition_variable not_full_{};
    bool shutdown_{false};
};

} // namespace dpi

#endif // DPI_PIPELINE_BOUNDED_QUEUE_H
