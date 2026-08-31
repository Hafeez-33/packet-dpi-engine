import struct
import socket

def create_sample_pcap(filepath: str = "sample_traffic.pcap"):
    packets = []

    def make_eth_ip_tcp(src_ip, src_port, dst_ip, dst_port, payload=b"", flags=0x18):
        eth = b"\x00" * 12 + struct.pack("!H", 0x0800)
        ip_len = 20 + 20 + len(payload)
        ip = struct.pack("!BBHHHBBH4s4s",
            0x45, 0, ip_len, 0x1234, 0x4000, 64, 6, 0,
            socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        tcp = struct.pack("!HHIIBBHHH",
            src_port, dst_port, 1000, 0, (5 << 4), flags, 65535, 0, 0)
        return eth + ip + tcp + payload

    def make_eth_ip_udp(src_ip, src_port, dst_ip, dst_port, payload=b""):
        eth = b"\x00" * 12 + struct.pack("!H", 0x0800)
        ip_len = 20 + 8 + len(payload)
        ip = struct.pack("!BBHHHBBH4s4s",
            0x45, 0, ip_len, 0x1234, 0x4000, 64, 17, 0,
            socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        udp = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0)
        return eth + ip + udp + payload

    # 1. TLS ClientHello with SNI "cloudflare.com"
    sni = b"cloudflare.com"
    ext_sni = struct.pack("!HHHBH", 0x0000, len(sni) + 5, len(sni) + 3, 0x00, len(sni)) + sni
    ext_all = struct.pack("!H", len(ext_sni)) + ext_sni
    ch_body = struct.pack("!H", 0x0303) + b"\x00"*32 + b"\x00" + struct.pack("!H", 2) + b"\x00\x2f" + b"\x01\x00" + ext_all
    handshake = struct.pack("!B", 0x01) + struct.pack("!I", len(ch_body))[1:] + ch_body
    tls_record = struct.pack("!BBHH", 0x16, 0x03, 0x01, len(handshake)) + handshake
    packets.append(make_eth_ip_tcp("192.168.1.10", 50100, "104.16.132.229", 443, tls_record))

    # 2. HTTP GET request
    http_req = b"GET /index.html HTTP/1.1\r\nHost: example.org\r\nUser-Agent: test\r\n\r\n"
    packets.append(make_eth_ip_tcp("192.168.1.11", 50101, "93.184.216.34", 80, http_req))

    # 3. DNS Query for "google.com"
    dns_query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01"
    packets.append(make_eth_ip_udp("192.168.1.12", 50102, "8.8.8.8", 53, dns_query))

    # 4. Blocked Traffic on Port 8080
    packets.append(make_eth_ip_tcp("192.168.1.13", 50103, "198.51.100.25", 8080, b"DATA"))

    # 5. Blocked Domain traffic (*.badactor.org)
    sni_bad = b"login.badactor.org"
    ext_sni_bad = struct.pack("!HHHBH", 0x0000, len(sni_bad) + 5, len(sni_bad) + 3, 0x00, len(sni_bad)) + sni_bad
    ext_all_bad = struct.pack("!H", len(ext_sni_bad)) + ext_sni_bad
    ch_body_bad = struct.pack("!H", 0x0303) + b"\x00"*32 + b"\x00" + struct.pack("!H", 2) + b"\x00\x2f" + b"\x01\x00" + ext_all_bad
    handshake_bad = struct.pack("!B", 0x01) + struct.pack("!I", len(ch_body_bad))[1:] + ch_body_bad
    tls_bad = struct.pack("!BBHH", 0x16, 0x03, 0x01, len(handshake_bad)) + handshake_bad
    packets.append(make_eth_ip_tcp("192.168.1.14", 50104, "198.51.100.50", 443, tls_bad))

    with open(filepath, "wb") as f:
        # PCAP Global Header
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        ts_sec = 1600000000
        ts_usec = 100000
        for pkt in packets:
            f.write(struct.pack("<IIII", ts_sec, ts_usec, len(pkt), len(pkt)))
            f.write(pkt)
            ts_usec += 10000

    print(f"Successfully generated '{filepath}' with {len(packets)} test packets.")

if __name__ == "__main__":
    create_sample_pcap()
