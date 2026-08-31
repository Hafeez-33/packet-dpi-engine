#!/usr/bin/env python3
"""
Generate a synthetic PCAP with C2 periodic beaconing, data exfiltration,
and normal background web traffic for Stage 9 validation.
"""
import struct
import sys
import os

def ip_to_bytes(ip_str):
    return bytes(map(int, ip_str.split('.')))

def create_tcp_packet(src_ip, dst_ip, src_port, dst_port, payload=b"", seq=1, ack=1, flags=0x18):
    # Ethernet (14)
    eth = b'\x00' * 12 + b'\x08\x00'
    
    # IPv4 (20)
    total_len = 20 + 20 + len(payload)
    ip = struct.pack(
        '!BBHHHBBH4s4s',
        0x45, 0, total_len, 0x1234, 0x4000, 64, 6, 0,
        ip_to_bytes(src_ip), ip_to_bytes(dst_ip)
    )
    
    # TCP (20)
    tcp = struct.pack(
        '!HHIIBBHHH',
        src_port, dst_port, seq, ack,
        0x50, flags, 0x1000, 0, 0
    )
    return eth + ip + tcp + payload

def main(output_file="beaconing_exfil_traffic.pcap"):
    print(f"Generating synthetic PCAP with beaconing and exfiltration: {output_file}")
    
    packets = [] # (ts_sec, ts_usec, pkt_bytes)
    
    # 1. Periodic C2 Beaconing Flow (192.168.1.100 -> 198.51.100.5:443)
    # 15 intervals with ~500ms spacing and minimal jitter (+/- 2ms)
    cur_ts_us = 1000000
    for i in range(16):
        pkt = create_tcp_packet(
            "192.168.1.100", "198.51.100.5", 55432, 443,
            b"\x16\x03\x01\x00\x10heartbeat_ping", seq=1 + i*20, ack=1
        )
        packets.append((cur_ts_us // 1000000, cur_ts_us % 1000000, pkt))
        cur_ts_us += 500000 + (2000 if i % 2 == 0 else -2000)

    # 2. Data Exfiltration Flow (192.168.1.150 -> 203.0.113.88:8080)
    # Heavy outbound forward data (1.2 MB forward vs tiny reverse ACK)
    cur_ts_us = 2000000
    chunk = b"A" * 1400
    for i in range(800): # 800 * 1400 = 1.12 MB
        pkt_fwd = create_tcp_packet(
            "192.168.1.150", "203.0.113.88", 60123, 8080,
            chunk, seq=1 + i*1400, ack=1
        )
        packets.append((cur_ts_us // 1000000, cur_ts_us % 1000000, pkt_fwd))
        cur_ts_us += 1000 # 1ms intervals
        
        # Occasional reverse ack (empty)
        if i % 100 == 0:
            pkt_rev = create_tcp_packet(
                "203.0.113.88", "192.168.1.150", 8080, 60123,
                b"", seq=1, ack=1 + (i+1)*1400, flags=0x10
            )
            packets.append((cur_ts_us // 1000000, cur_ts_us % 1000000, pkt_rev))

    # 3. Normal Background Web Traffic (High Jitter & Balanced)
    cur_ts_us = 1500000
    normal_deltas = [150000, 2400000, 80000, 3500000, 450000, 1800000, 90000, 4000000]
    for d in normal_deltas:
        cur_ts_us += d
        pkt = create_tcp_packet(
            "192.168.1.200", "93.184.216.34", 49152, 80,
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        )
        packets.append((cur_ts_us // 1000000, cur_ts_us % 1000000, pkt))

    # Sort all packets strictly by timestamp
    packets.sort(key=lambda p: (p[0], p[1]))

    # Write PCAP
    with open(output_file, 'wb') as f:
        # Global Header (24)
        f.write(struct.pack('!IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        
        for ts_sec, ts_usec, pkt_bytes in packets:
            caplen = len(pkt_bytes)
            f.write(struct.pack('!IIII', ts_sec, ts_usec, caplen, caplen))
            f.write(pkt_bytes)

    print(f"Successfully generated {len(packets)} packets in {output_file}")

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "beaconing_exfil_traffic.pcap"
    main(out)
