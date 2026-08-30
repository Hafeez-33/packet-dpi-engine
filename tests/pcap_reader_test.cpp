#include <iostream>
#include <sstream>
#include <vector>
#include <cassert>
#include <cstring>
#include "dpi/packet/pcap_reader.h"

using namespace dpi;

static void write_u16(std::ostream& os, uint16_t val, bool be = false) {
    if (be) val = bswap16(val);
    os.write(reinterpret_cast<const char*>(&val), sizeof(val));
}

static void write_u32(std::ostream& os, uint32_t val, bool be = false) {
    if (be) val = bswap32(val);
    os.write(reinterpret_cast<const char*>(&val), sizeof(val));
}

static std::string make_global_header(uint32_t magic, uint16_t major, uint16_t minor,
                                      int32_t thiszone, uint32_t sigfigs,
                                      uint32_t snaplen, uint32_t network) {
    std::stringstream ss(std::ios::in | std::ios::out | std::ios::binary);
    bool be = (magic == pcap_magic::MICROSEC_SWAPPED || magic == pcap_magic::NANOSEC_SWAPPED);
    
    ss.write(reinterpret_cast<const char*>(&magic), sizeof(magic));
    write_u16(ss, major, be);
    write_u16(ss, minor, be);
    write_u32(ss, static_cast<uint32_t>(thiszone), be);
    write_u32(ss, sigfigs, be);
    write_u32(ss, snaplen, be);
    write_u32(ss, network, be);
    return ss.str();
}

static std::string make_packet_hdr(uint32_t ts_sec, uint32_t ts_usec,
                                   uint32_t incl_len, uint32_t orig_len, bool be = false) {
    std::stringstream ss(std::ios::in | std::ios::out | std::ios::binary);
    write_u32(ss, ts_sec, be);
    write_u32(ss, ts_usec, be);
    write_u32(ss, incl_len, be);
    write_u32(ss, orig_len, be);
    return ss.str();
}

void test_valid_little_endian() {
    std::cout << "[TEST] Valid Little-Endian PCAP..." << std::endl;
    std::string data = make_global_header(pcap_magic::MICROSEC_NATIVE, 2, 4, 0, 0, 65535, 1);
    std::stringstream ss(data, std::ios::in | std::ios::binary);

    PcapReader reader;
    PcapErrorCode err = reader.open(ss);
    assert(err == PcapErrorCode::Success);
    assert(reader.is_open());
    assert(!reader.global_header().is_byte_swapped);
    assert(reader.global_header().version_major == 2);
    assert(reader.global_header().version_minor == 4);
    assert(reader.global_header().snaplen == 65535);
    assert(reader.global_header().network == 1);
}

void test_valid_big_endian() {
    std::cout << "[TEST] Valid Big-Endian PCAP..." << std::endl;
    std::string data = make_global_header(pcap_magic::MICROSEC_SWAPPED, 2, 4, 0, 0, 65535, 1);
    std::stringstream ss(data, std::ios::in | std::ios::binary);

    PcapReader reader;
    PcapErrorCode err = reader.open(ss);
    assert(err == PcapErrorCode::Success);
    assert(reader.is_open());
    assert(reader.global_header().is_byte_swapped);
    assert(reader.global_header().version_major == 2);
    assert(reader.global_header().version_minor == 4);
    assert(reader.global_header().snaplen == 65535);
    assert(reader.global_header().network == 1);
}

void test_empty_pcap() {
    std::cout << "[TEST] Empty PCAP (0 bytes & 0 packets)..." << std::endl;
    {
        std::stringstream ss("", std::ios::in | std::ios::binary);
        PcapReader reader;
        assert(reader.open(ss) == PcapErrorCode::TruncatedGlobalHeader);
    }
    {
        std::string hdr = make_global_header(pcap_magic::MICROSEC_NATIVE, 2, 4, 0, 0, 65535, 1);
        std::stringstream ss(hdr, std::ios::in | std::ios::binary);
        PcapReader reader;
        assert(reader.open(ss) == PcapErrorCode::Success);

        PacketRecord rec;
        assert(reader.read_next_packet(rec) == PcapErrorCode::EndOfFile);
    }
}

void test_truncated_global_header() {
    std::cout << "[TEST] Truncated Global Header..." << std::endl;
    std::string data = make_global_header(pcap_magic::MICROSEC_NATIVE, 2, 4, 0, 0, 65535, 1);
    std::string truncated = data.substr(0, 15);
    std::stringstream ss(truncated, std::ios::in | std::ios::binary);

    PcapReader reader;
    assert(reader.open(ss) == PcapErrorCode::TruncatedGlobalHeader);
}

void test_truncated_packet_header() {
    std::cout << "[TEST] Truncated Packet Header..." << std::endl;
    std::string data = make_global_header(pcap_magic::MICROSEC_NATIVE, 2, 4, 0, 0, 65535, 1);
    std::string pkt_hdr = make_packet_hdr(100, 200, 10, 10, false);
    data += pkt_hdr.substr(0, 8); // Only 8 bytes of 16-byte packet header

    std::stringstream ss(data, std::ios::in | std::ios::binary);
    PcapReader reader;
    assert(reader.open(ss) == PcapErrorCode::Success);

    PacketRecord rec;
    assert(reader.read_next_packet(rec) == PcapErrorCode::TruncatedPacketHeader);
}

void test_truncated_packet_data() {
    std::cout << "[TEST] Truncated Packet Data..." << std::endl;
    std::string data = make_global_header(pcap_magic::MICROSEC_NATIVE, 2, 4, 0, 0, 65535, 1);
    data += make_packet_hdr(100, 200, 10, 10, false);
    data += "12345"; // Only 5 bytes of 10-byte payload

    std::stringstream ss(data, std::ios::in | std::ios::binary);
    PcapReader reader;
    assert(reader.open(ss) == PcapErrorCode::Success);

    PacketRecord rec;
    assert(reader.read_next_packet(rec) == PcapErrorCode::TruncatedPacketData);
}

void test_invalid_magic_number() {
    std::cout << "[TEST] Invalid Magic Number..." << std::endl;
    std::string data = make_global_header(0xDEADBEEF, 2, 4, 0, 0, 65535, 1);
    std::stringstream ss(data, std::ios::in | std::ios::binary);

    PcapReader reader;
    assert(reader.open(ss) == PcapErrorCode::InvalidMagicNumber);
}

void test_unsupported_version() {
    std::cout << "[TEST] Unsupported Version..." << std::endl;
    std::string data = make_global_header(pcap_magic::MICROSEC_NATIVE, 1, 0, 0, 0, 65535, 1);
    std::stringstream ss(data, std::ios::in | std::ios::binary);

    PcapReader reader;
    assert(reader.open(ss) == PcapErrorCode::UnsupportedVersion);
}

void test_multi_packet_pcap() {
    std::cout << "[TEST] Multi-Packet PCAP..." << std::endl;
    std::string data = make_global_header(pcap_magic::MICROSEC_NATIVE, 2, 4, 0, 0, 65535, 1);

    // Packet 1
    std::vector<uint8_t> p1_payload = {'H', 'e', 'l', 'l', 'o'};
    data += make_packet_hdr(1600000000, 100, static_cast<uint32_t>(p1_payload.size()), 64, false);
    data.append(reinterpret_cast<const char*>(p1_payload.data()), p1_payload.size());

    // Packet 2
    std::vector<uint8_t> p2_payload = {'W', 'o', 'r', 'l', 'd', '!'};
    data += make_packet_hdr(1600000001, 250, static_cast<uint32_t>(p2_payload.size()), 128, false);
    data.append(reinterpret_cast<const char*>(p2_payload.data()), p2_payload.size());

    // Packet 3
    std::vector<uint8_t> p3_payload = {0x00, 0x01, 0x02, 0x03, 0x04};
    data += make_packet_hdr(1600000002, 500, static_cast<uint32_t>(p3_payload.size()), 5, false);
    data.append(reinterpret_cast<const char*>(p3_payload.data()), p3_payload.size());

    std::stringstream ss(data, std::ios::in | std::ios::binary);
    PcapReader reader;
    assert(reader.open(ss) == PcapErrorCode::Success);

    PacketRecord rec;

    // Verify Packet 1
    assert(reader.read_next_packet(rec) == PcapErrorCode::Success);
    assert(rec.header.ts_sec == 1600000000);
    assert(rec.header.ts_usec == 100);
    assert(rec.header.incl_len == 5);
    assert(rec.header.orig_len == 64);
    assert(rec.payload == p1_payload);

    // Verify Packet 2
    assert(reader.read_next_packet(rec) == PcapErrorCode::Success);
    assert(rec.header.ts_sec == 1600000001);
    assert(rec.header.ts_usec == 250);
    assert(rec.header.incl_len == 6);
    assert(rec.header.orig_len == 128);
    assert(rec.payload == p2_payload);

    // Verify Packet 3
    assert(reader.read_next_packet(rec) == PcapErrorCode::Success);
    assert(rec.header.ts_sec == 1600000002);
    assert(rec.header.ts_usec == 500);
    assert(rec.header.incl_len == 5);
    assert(rec.header.orig_len == 5);
    assert(rec.payload == p3_payload);

    // Verify clean EOF after final packet
    assert(reader.read_next_packet(rec) == PcapErrorCode::EndOfFile);
}

void test_max_packet_size_limit() {
    std::cout << "[TEST] Configurable Max Packet Size Limit..." << std::endl;
    std::string data = make_global_header(pcap_magic::MICROSEC_NATIVE, 2, 4, 0, 0, 65535, 1);
    
    // Packet with 200 bytes captured length
    std::vector<uint8_t> payload(200, 'A');
    data += make_packet_hdr(100, 200, 200, 200, false);
    data.append(reinterpret_cast<const char*>(payload.data()), payload.size());

    std::stringstream ss(data, std::ios::in | std::ios::binary);
    PcapReader reader;
    assert(reader.open(ss) == PcapErrorCode::Success);

    // Restrict max packet size limit to 100 bytes
    reader.set_max_packet_size(100);

    PacketRecord rec;
    assert(reader.read_next_packet(rec) == PcapErrorCode::PacketExceedsMaxLimit);
}

void test_corrupt_packet_length() {
    std::cout << "[TEST] Corrupt Packet Length (exceeds snaplen)..." << std::endl;
    std::string data = make_global_header(pcap_magic::MICROSEC_NATIVE, 2, 4, 0, 0, 1500, 1);
    
    // Packet with incl_len 2000 exceeding snaplen 1500
    data += make_packet_hdr(100, 200, 2000, 2000, false);

    std::stringstream ss(data, std::ios::in | std::ios::binary);
    PcapReader reader;
    assert(reader.open(ss) == PcapErrorCode::Success);

    PacketRecord rec;
    assert(reader.read_next_packet(rec) == PcapErrorCode::CorruptPacketLength);
}

int main() {
    std::cout << "===========================================\n";
    std::cout << "  Running PCAP Reader Unit Test Suite     \n";
    std::cout << "===========================================\n";

    test_valid_little_endian();
    test_valid_big_endian();
    test_empty_pcap();
    test_truncated_global_header();
    test_truncated_packet_header();
    test_truncated_packet_data();
    test_invalid_magic_number();
    test_unsupported_version();
    test_multi_packet_pcap();
    test_max_packet_size_limit();
    test_corrupt_packet_length();

    std::cout << "===========================================\n";
    std::cout << "  ALL PCAP READER TESTS PASSED SUCCESSFULLY \n";
    std::cout << "===========================================\n";

    return 0;
}
