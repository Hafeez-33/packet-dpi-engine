#!/usr/bin/env python3
"""
generate_malicious_pcap.py
Generates a multi-vector test PCAP file containing benign traffic along with:
1. Vertical Port Scan (single host, multiple ports)
2. Horizontal Port Scan (subnet sweep, single port)
3. TCP SYN Flood (burst of unacknowledged SYNs)
4. DNS Tunneling & DGA High-Entropy Queries
5. Web Attacks: SQL Injection, Path Traversal, and Scanner User-Agents (sqlmap, masscan, nikto)
"""

import struct
import socket

def create_ipv4_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                       proto: int = 6, flags: int = 0x02, payload: bytes = b"") -> bytes:
    # 1. Ethernet Header (14 bytes)
    eth_header = b"\x00\x11\x22\x33\x44\x55\x00\xaa\xbb\xcc\xdd\xee\x08\x00"

    # 2. IP Header (20 bytes)
    ihl_ver = 0x45
    tos = 0
    total_len = 20 + 20 + len(payload) if proto == 6 else 20 + 8 + len(payload)
    ident = 0x1234
    flags_frag = 0x4000
    ttl = 64
    chksum = 0
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)

    ip_header = struct.pack("!BBHHHBBH4s4s",
                            ihl_ver, tos, total_len, ident, flags_frag,
                            ttl, proto, chksum, src_bytes, dst_bytes)

    # 3. Transport Header
    if proto == 6: # TCP
        seq = 1000
        ack_seq = 0
        offset_res = (5 << 4)
        window = 65535
        urgent = 0
        tcp_header = struct.pack("!HHIIBBHHH",
                                 src_port, dst_port, seq, ack_seq,
                                 offset_res, flags, window, chksum, urgent)
        return eth_header + ip_header + tcp_header + payload
    elif proto == 17: # UDP
        udp_len = 8 + len(payload)
        udp_header = struct.pack("!HHHH", src_port, dst_port, udp_len, chksum)
        return eth_header + ip_header + udp_header + payload
    else:
        return eth_header + ip_header + payload

def encode_dns_query(domain: str, tx_id: int = 0x1234) -> bytes:
    # DNS Header (12 bytes)
    flags = 0x0100 # Standard Query
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0
    header = struct.pack("!HHHHHH", tx_id, flags, qdcount, ancount, nscount, arcount)

    # Question Section
    qname = b""
    for label in domain.split("."):
        if label:
            l_bytes = label.encode("latin-1")
            qname += bytes([len(l_bytes)]) + l_bytes
    qname += b"\x00"
    qtype = 1 # A Record
    qclass = 1 # IN Class
    question = qname + struct.pack("!HH", qtype, qclass)

    return header + question

def write_pcap(filename: str = "malicious_traffic.pcap"):
    packets = []
    ts_sec = 1600000000
    ts_usec = 0

    def add_pkt(pkt_data: bytes):
        nonlocal ts_sec, ts_usec
        ts_usec += 1000
        if ts_usec >= 1000000:
            ts_sec += 1
            ts_usec = 0
        packets.append((ts_sec, ts_usec, pkt_data))

    # --- 1. Benign Web & DNS Traffic ---
    benign_http = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    add_pkt(create_ipv4_packet("192.168.1.100", "93.184.216.34", 45000, 80, 6, 0x18, benign_http))
    dns_benign = encode_dns_query("example.com")
    add_pkt(create_ipv4_packet("192.168.1.100", "8.8.8.8", 45001, 53, 17, 0, dns_benign))

    # --- 2. Vertical Port Scan ---
    # Attacker 192.168.1.50 scans target 10.0.0.1 on ports 20..45
    for port in range(20, 45):
        add_pkt(create_ipv4_packet("192.168.1.50", "10.0.0.1", 54321, port, 6, 0x02))

    # --- 3. Horizontal Port Scan ---
    # Attacker 192.168.1.55 sweeps subnet 10.0.0.1..10.0.0.30 on port 80
    for i in range(1, 31):
        add_pkt(create_ipv4_packet("192.168.1.55", f"10.0.0.{i}", 54322, 80, 6, 0x02))

    # --- 4. TCP SYN Flood ---
    # Attacker 192.168.1.66 floods target 10.0.0.5:443 with 60 unacknowledged SYNs
    for i in range(1000, 1060):
        add_pkt(create_ipv4_packet("192.168.1.66", "10.0.0.5", i, 443, 6, 0x02))

    # --- 5. DNS Tunneling & DGA High-Entropy Anomaly ---
    dga_domain = "a9b8c7d6e5f4g3h2i1j0k9l8m7n6.tunnel.exfiltration-c2.net"
    add_pkt(create_ipv4_packet("192.168.1.77", "8.8.8.8", 53000, 53, 17, 0, encode_dns_query(dga_domain)))

    long_label = "thisisaverylongsubdomainlabelusedbydataexfiltrationattackersexceedingthethreshold.evil.org"
    add_pkt(create_ipv4_packet("192.168.1.77", "8.8.8.8", 53001, 53, 17, 0, encode_dns_query(long_label)))

    # --- 6. SQL Injection ---
    sqli_1 = b"GET /products?id=10%20UNION%20SELECT%20username,password%20FROM%20admin HTTP/1.1\r\nHost: vulnerable-app.internal\r\n\r\n"
    add_pkt(create_ipv4_packet("192.168.1.88", "10.0.0.20", 61000, 8080, 6, 0x18, sqli_1))

    sqli_2 = b"POST /login HTTP/1.1\r\nHost: target.com\r\nContent-Length: 30\r\n\r\nusername=' OR 1=1--&pass=x"
    add_pkt(create_ipv4_packet("192.168.1.88", "10.0.0.20", 61001, 8080, 6, 0x18, sqli_2))

    # --- 7. Path Traversal ---
    traversal = b"GET /api/download?file=../../../../etc/passwd HTTP/1.1\r\nHost: target.com\r\n\r\n"
    add_pkt(create_ipv4_packet("192.168.1.88", "10.0.0.20", 61002, 8080, 6, 0x18, traversal))

    # --- 8. Scanner User-Agents ---
    masscan_req = b"GET / HTTP/1.0\r\nUser-Agent: masscan/1.3.2 (https://github.com/robertdavidgraham/masscan)\r\n\r\n"
    add_pkt(create_ipv4_packet("192.168.1.99", "10.0.0.30", 55555, 80, 6, 0x18, masscan_req))

    sqlmap_req = b"GET /vuln.php?id=1 HTTP/1.1\r\nHost: target.com\r\nUser-Agent: sqlmap/1.6#stable\r\n\r\n"
    add_pkt(create_ipv4_packet("192.168.1.99", "10.0.0.30", 55556, 80, 6, 0x18, sqlmap_req))

    with open(filename, "wb") as f:
        # PCAP Global Header
        f.write(struct.pack("!IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for sec, usec, data in packets:
            hdr = struct.pack("!IIII", sec, usec, len(data), len(data))
            f.write(hdr + data)

    print(f"[+] Successfully generated {filename} with {len(packets)} packets containing multi-vector threats!")

if __name__ == "__main__":
    write_pcap()
