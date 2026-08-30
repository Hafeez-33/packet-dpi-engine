#include "dpi/packet/pcap_reader.h"
#include <cstring>
#include <utility>

namespace dpi {

std::string_view pcap_error_to_string(PcapErrorCode code) noexcept {
    switch (code) {
        case PcapErrorCode::Success:                return "Success";
        case PcapErrorCode::FileNotFound:           return "File not found or failed to open";
        case PcapErrorCode::StreamError:            return "Stream error encountered";
        case PcapErrorCode::TruncatedGlobalHeader:  return "Truncated global header (< 24 bytes)";
        case PcapErrorCode::InvalidMagicNumber:     return "Invalid PCAP magic number";
        case PcapErrorCode::UnsupportedVersion:    return "Unsupported PCAP version (expected 2.4)";
        case PcapErrorCode::InvalidSnaplen:         return "Invalid snaplen in global header (must be > 0)";
        case PcapErrorCode::TruncatedPacketHeader:  return "Truncated packet record header (< 16 bytes)";
        case PcapErrorCode::TruncatedPacketData:    return "Truncated packet payload data";
        case PcapErrorCode::CorruptPacketLength:    return "Corrupted packet length (captured length exceeds snaplen)";
        case PcapErrorCode::PacketExceedsMaxLimit:  return "Packet captured length exceeds configured maximum safety limit";
        case PcapErrorCode::EndOfFile:             return "End of file reached cleanly";
    }
    return "Unknown PCAP error";
}

PcapReader::~PcapReader() {
    close();
}

PcapReader::PcapReader(PcapReader&& other) noexcept {
    *this = std::move(other);
}

PcapReader& PcapReader::operator=(PcapReader&& other) noexcept {
    if (this != &other) {
        close();
        file_stream_ = std::move(other.file_stream_);
        if (other.stream_ == &other.file_stream_) {
            stream_ = &file_stream_;
        } else {
            stream_ = other.stream_;
        }
        global_header_ = other.global_header_;
        is_open_ = other.is_open_;
        max_packet_size_ = other.max_packet_size_;

        other.stream_ = nullptr;
        other.is_open_ = false;
        other.global_header_ = GlobalHeader{};
    }
    return *this;
}

void PcapReader::close() {
    if (file_stream_.is_open()) {
        file_stream_.close();
    }
    stream_ = nullptr;
    is_open_ = false;
    global_header_ = GlobalHeader{};
}

PcapErrorCode PcapReader::open(const std::string& filepath) {
    close();
    file_stream_.open(filepath, std::ios::binary);
    if (!file_stream_.is_open() || !file_stream_.good()) {
        return PcapErrorCode::FileNotFound;
    }
    return open(file_stream_);
}

PcapErrorCode PcapReader::open(std::istream& stream) {
    if (&file_stream_ != &stream) {
        close();
    }
    stream_ = &stream;
    if (!stream_ || !stream_->good()) {
        return PcapErrorCode::StreamError;
    }
    PcapErrorCode err = parse_global_header();
    if (err != PcapErrorCode::Success) {
        close();
        return err;
    }
    is_open_ = true;
    return PcapErrorCode::Success;
}

PcapErrorCode PcapReader::parse_global_header() {
    uint8_t raw_header[24];
    stream_->read(reinterpret_cast<char*>(raw_header), sizeof(raw_header));
    std::streamsize bytes_read = stream_->gcount();

    if (bytes_read < static_cast<std::streamsize>(sizeof(raw_header))) {
        return PcapErrorCode::TruncatedGlobalHeader;
    }

    uint32_t magic;
    std::memcpy(&magic, raw_header, sizeof(uint32_t));

    bool swapped = false;
    bool nanosec = false;

    if (magic == pcap_magic::MICROSEC_NATIVE) {
        swapped = false;
        nanosec = false;
    } else if (magic == pcap_magic::MICROSEC_SWAPPED) {
        swapped = true;
        nanosec = false;
    } else if (magic == pcap_magic::NANOSEC_NATIVE) {
        swapped = false;
        nanosec = true;
    } else if (magic == pcap_magic::NANOSEC_SWAPPED) {
        swapped = true;
        nanosec = true;
    } else {
        return PcapErrorCode::InvalidMagicNumber;
    }

    auto read_u16 = [swapped](const uint8_t* ptr) -> uint16_t {
        uint16_t val;
        std::memcpy(&val, ptr, sizeof(uint16_t));
        return swapped ? bswap16(val) : val;
    };

    auto read_u32 = [swapped](const uint8_t* ptr) -> uint32_t {
        uint32_t val;
        std::memcpy(&val, ptr, sizeof(uint32_t));
        return swapped ? bswap32(val) : val;
    };

    uint16_t major = read_u16(raw_header + 4);
    uint16_t minor = read_u16(raw_header + 6);
    int32_t thiszone = static_cast<int32_t>(read_u32(raw_header + 8));
    uint32_t sigfigs = read_u32(raw_header + 12);
    uint32_t snaplen = read_u32(raw_header + 16);
    uint32_t network = read_u32(raw_header + 20);

    // Isolated version validation for classic PCAP (version 2.4)
    if (major != pcap_version::MAJOR_REQUIRED || minor != pcap_version::MINOR_REQUIRED) {
        return PcapErrorCode::UnsupportedVersion;
    }

    if (snaplen == 0) {
        return PcapErrorCode::InvalidSnaplen;
    }

    global_header_.magic_number = magic;
    global_header_.version_major = major;
    global_header_.version_minor = minor;
    global_header_.thiszone = thiszone;
    global_header_.sigfigs = sigfigs;
    global_header_.snaplen = snaplen;
    global_header_.network = network;
    global_header_.is_byte_swapped = swapped;
    global_header_.is_nanosecond_resolution = nanosec;

    return PcapErrorCode::Success;
}

PcapErrorCode PcapReader::read_next_packet(PacketRecord& record) {
    if (!is_open_ || !stream_) {
        return PcapErrorCode::StreamError;
    }

    // Peek stream to check if at end of file cleanly
    if (stream_->peek() == std::char_traits<char>::eof()) {
        return PcapErrorCode::EndOfFile;
    }

    uint8_t raw_hdr[16];
    stream_->read(reinterpret_cast<char*>(raw_hdr), sizeof(raw_hdr));
    std::streamsize bytes_read = stream_->gcount();

    if (bytes_read == 0) {
        return PcapErrorCode::EndOfFile;
    }

    if (bytes_read < static_cast<std::streamsize>(sizeof(raw_hdr))) {
        return PcapErrorCode::TruncatedPacketHeader;
    }

    bool swapped = global_header_.is_byte_swapped;
    auto read_u32 = [swapped](const uint8_t* ptr) -> uint32_t {
        uint32_t val;
        std::memcpy(&val, ptr, sizeof(uint32_t));
        return swapped ? bswap32(val) : val;
    };

    uint32_t ts_sec  = read_u32(raw_hdr);
    uint32_t ts_usec = read_u32(raw_hdr + 4);
    uint32_t incl_len = read_u32(raw_hdr + 8);
    uint32_t orig_len = read_u32(raw_hdr + 12);

    // Validation checks on packet captured length
    if (incl_len > global_header_.snaplen) {
        return PcapErrorCode::CorruptPacketLength;
    }

    if (incl_len > max_packet_size_) {
        return PcapErrorCode::PacketExceedsMaxLimit;
    }

    record.header.ts_sec = ts_sec;
    record.header.ts_usec = ts_usec;
    record.header.incl_len = incl_len;
    record.header.orig_len = orig_len;

    record.payload.resize(incl_len);

    if (incl_len > 0) {
        stream_->read(reinterpret_cast<char*>(record.payload.data()), incl_len);
        std::streamsize payload_bytes_read = stream_->gcount();
        if (payload_bytes_read < static_cast<std::streamsize>(incl_len)) {
            return PcapErrorCode::TruncatedPacketData;
        }
    }

    return PcapErrorCode::Success;
}

} // namespace dpi
