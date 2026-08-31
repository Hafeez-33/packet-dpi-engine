#include "dpi/flow/tcp_state_machine.h"

namespace dpi {

void TcpStateMachine::reset() noexcept {
    state_ = TcpState::New;
    syn_seen_fwd_ = false;
    syn_seen_rev_ = false;
    fin_seen_fwd_ = false;
    fin_seen_rev_ = false;
    rst_seen_ = false;
}

void TcpStateMachine::process_packet(const TcpHeader& tcp, FlowDirection dir, size_t payload_len) noexcept {
    // 1. RST processing - terminates connection immediately from any state
    if (tcp.flags.rst) {
        rst_seen_ = true;
        state_ = TcpState::Reset;
        return;
    }

    // 2. Handle re-initialization on closed / reset state if a new SYN arrives
    if (state_ == TcpState::Closed || state_ == TcpState::Reset) {
        if (tcp.flags.syn) {
            reset();
        } else {
            return; // Ignore non-SYN packets for already terminated flows
        }
    }

    // 3. FIN processing - connection teardown
    if (tcp.flags.fin) {
        if (dir == FlowDirection::Forward) {
            fin_seen_fwd_ = true;
        } else {
            fin_seen_rev_ = true;
        }

        if (fin_seen_fwd_ && fin_seen_rev_) {
            // Simultaneous FIN or bidirectional FIN seen
            state_ = TcpState::Closed;
        } else {
            if (dir == FlowDirection::Forward) {
                state_ = TcpState::FinWait;
            } else {
                state_ = TcpState::CloseWait;
            }
        }
        return;
    }

    // If currently in a closing state, check for ACKs to complete teardown
    if (state_ == TcpState::FinWait || state_ == TcpState::CloseWait || state_ == TcpState::Closing || state_ == TcpState::LastAck) {
        if (fin_seen_fwd_ && fin_seen_rev_) {
            state_ = TcpState::Closed;
            return;
        }
        if (tcp.flags.ack) {
            if (state_ == TcpState::FinWait && dir == FlowDirection::Reverse) {
                state_ = TcpState::Closing;
            } else if (state_ == TcpState::CloseWait && dir == FlowDirection::Forward) {
                state_ = TcpState::Closing;
            }
        }
        return;
    }

    // 4. SYN processing - 3-way handshake tracking
    if (tcp.flags.syn) {
        if (tcp.flags.ack) {
            // SYN-ACK (typically from responder/server)
            if (dir == FlowDirection::Forward) {
                syn_seen_fwd_ = true;
            } else {
                syn_seen_rev_ = true;
            }
            state_ = TcpState::SynReceived;
        } else {
            // Pure SYN (typically from initiator/client)
            if (dir == FlowDirection::Forward) {
                syn_seen_fwd_ = true;
            } else {
                syn_seen_rev_ = true;
            }
            if (state_ == TcpState::New) {
                state_ = TcpState::SynSent;
            }
        }
        return;
    }

    // 5. ACK or Data packet processing
    if (tcp.flags.ack || payload_len > 0) {
        if (state_ == TcpState::New) {
            // Mid-stream pickup: flow observed after handshake completed
            state_ = TcpState::Established;
        } else if (state_ == TcpState::SynSent || state_ == TcpState::SynReceived) {
            // Final ACK of the 3-way handshake or early data
            state_ = TcpState::Established;
        }
    }
}

} // namespace dpi
