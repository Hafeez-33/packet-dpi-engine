#ifndef DPI_FLOW_TCP_STATE_MACHINE_H
#define DPI_FLOW_TCP_STATE_MACHINE_H

#include "dpi/flow/flow_types.h"
#include "dpi/protocols/tcp.h"
#include <cstddef>
#include <cstdint>

namespace dpi {

/**
 * @brief Robust observational TCP state tracker.
 * 
 * Tracks TCP flow state transitions across 3-way handshake, bidirectional data exchange,
 * and connection teardown (FIN/RST). Designed to handle out-of-order packets, mid-stream pickups,
 * missing handshake packets, retransmissions, and simultaneous FINs gracefully.
 */
class TcpStateMachine {
public:
    TcpStateMachine() = default;

    TcpState state() const noexcept { return state_; }
    bool is_established() const noexcept { return state_ == TcpState::Established; }
    bool is_closed() const noexcept { return state_ == TcpState::Closed || state_ == TcpState::Reset; }

    bool syn_seen_forward() const noexcept { return syn_seen_fwd_; }
    bool syn_seen_reverse() const noexcept { return syn_seen_rev_; }
    bool fin_seen_forward() const noexcept { return fin_seen_fwd_; }
    bool fin_seen_reverse() const noexcept { return fin_seen_rev_; }
    bool rst_seen() const noexcept { return rst_seen_; }

    /**
     * @brief Process incoming TCP header and payload, updating the internal flow state.
     * @param tcp Parsed TCP header
     * @param dir Packet direction relative to flow canonical key
     * @param payload_len Length of L7 payload in bytes
     */
    void process_packet(const TcpHeader& tcp, FlowDirection dir, size_t payload_len) noexcept;

    /**
     * @brief Resets the state machine to initial clean state.
     */
    void reset() noexcept;

private:
    TcpState state_{TcpState::New};
    bool syn_seen_fwd_{false};
    bool syn_seen_rev_{false};
    bool fin_seen_fwd_{false};
    bool fin_seen_rev_{false};
    bool rst_seen_{false};
};

} // namespace dpi

#endif // DPI_FLOW_TCP_STATE_MACHINE_H
