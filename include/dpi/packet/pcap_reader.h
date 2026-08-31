#ifndef DPI_PCAP_READER_H
#define DPI_PCAP_READER_H

#include "dpi/packet/pcap_types.h"
#include <fstream>
#include <iostream>
#include <string>

namespace dpi {

/**
 * @brief RAII PCAP file/stream reader for classic .pcap files.
 * 
 * Supports streaming packet records sequentially, reading both little-endian
 * and big-endian files, bounds validation, and configurable memory safety limits.
 */
class PcapReader {
public:
    // Default maximum packet size safety limit (64 KB)
    static constexpr uint32_t DEFAULT_MAX_PACKET_SIZE = 65535;

    PcapReader() = default;
    ~PcapReader();

    // Disable copy semantics to manage file handle safety
    PcapReader(const PcapReader&) = delete;
    PcapReader& operator=(const PcapReader&) = delete;

    // Allow move semantics
    PcapReader(PcapReader&& other) noexcept;
    PcapReader& operator=(PcapReader&& other) noexcept;

    /**
     * @brief Open a PCAP file from disk (PcapReader manages file lifecycle).
     * @param filepath Path to the .pcap file
     * @return PcapErrorCode::Success or error code
     */
    PcapErrorCode open(const std::string& filepath);

    /**
     * @brief Open from a non-owning std::istream reference (ideal for testing in-memory streams).
     * @param stream Reference to input stream
     * @return PcapErrorCode::Success or error code
     */
    PcapErrorCode open(std::istream& stream);

    /**
     * @brief Reads the next packet record sequentially from the stream.
     * @param record Output structure populated with packet header and payload
     * @return PcapErrorCode::Success, PcapErrorCode::EndOfFile, or error code
     */
    PcapErrorCode read_next_packet(PacketRecord& record);

    /**
     * @brief Returns global header metadata.
     */
    const GlobalHeader& global_header() const noexcept { return global_header_; }

    /**
     * @brief Returns true if reader is open and global header has been validated.
     */
    bool is_open() const noexcept { return is_open_; }

    /**
     * @brief Set maximum allowed packet captured length safety limit.
     */
    void set_max_packet_size(uint32_t max_bytes) noexcept { max_packet_size_ = max_bytes; }
    uint32_t max_packet_size() const noexcept { return max_packet_size_; }

    /**
     * @brief Closes stream and resets internal reader state.
     */
    void close();

private:
    PcapErrorCode parse_global_header();

    std::ifstream file_stream_;
    std::istream* stream_{nullptr};
    GlobalHeader global_header_{};
    bool is_open_{false};
    uint32_t max_packet_size_{DEFAULT_MAX_PACKET_SIZE};
};

} // namespace dpi

#endif // DPI_PCAP_READER_H
