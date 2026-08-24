#!/usr/bin/env python3
"""Generate deterministic, offline Wireshark practice captures.

The captures use only private or documentation-only IP address ranges and never
send traffic.  They are byte-for-byte synthetic Ethernet/raw-IPv4 PCAP files.
"""

from __future__ import annotations

import ipaddress
import itertools
import socket
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW_IPV4 = 101

BASE_EPOCH = datetime(2026, 8, 24, 5, 0, 0, tzinfo=timezone.utc).timestamp()
IP_IDS = itertools.count(0x1000)


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def mac_bytes(value: str) -> bytes:
    return bytes.fromhex(value.replace(":", ""))


def ip_bytes(value: str) -> bytes:
    return ipaddress.IPv4Address(value).packed


def ethernet(src_mac: str, dst_mac: str, payload: bytes, ethertype: int = 0x0800) -> bytes:
    frame = mac_bytes(dst_mac) + mac_bytes(src_mac) + struct.pack("!H", ethertype) + payload
    return frame + (b"\x00" * max(0, 60 - len(frame)))


def ipv4(src_ip: str, dst_ip: str, protocol: int, payload: bytes, *, ttl: int = 64,
         identification: int | None = None) -> bytes:
    if identification is None:
        identification = next(IP_IDS) & 0xFFFF
    version_ihl = 0x45
    total_length = 20 + len(payload)
    flags_fragment = 0x4000  # Don't Fragment
    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol,
        0,
        ip_bytes(src_ip),
        ip_bytes(dst_ip),
    )
    header_checksum = checksum(header)
    header = header[:10] + struct.pack("!H", header_checksum) + header[12:]
    return header + payload


def tcp(src_ip: str, dst_ip: str, src_port: int, dst_port: int, seq: int, ack: int,
        flags: int, payload: bytes = b"", window: int = 64240) -> bytes:
    offset_flags = (5 << 12) | flags
    header = struct.pack("!HHIIHHHH", src_port, dst_port, seq, ack, offset_flags, window, 0, 0)
    pseudo = ip_bytes(src_ip) + ip_bytes(dst_ip) + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    tcp_checksum = checksum(pseudo + header + payload)
    header = header[:16] + struct.pack("!H", tcp_checksum) + header[18:]
    return header + payload


def udp(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    header = struct.pack("!HHHH", src_port, dst_port, length, 0)
    pseudo = ip_bytes(src_ip) + ip_bytes(dst_ip) + struct.pack("!BBH", 0, 17, length)
    udp_checksum = checksum(pseudo + header + payload) or 0xFFFF
    return struct.pack("!HHHH", src_port, dst_port, length, udp_checksum) + payload


def tcp_frame(src_mac: str, dst_mac: str, src_ip: str, dst_ip: str, src_port: int,
              dst_port: int, seq: int, ack: int, flags: int, payload: bytes = b"",
              *, ttl: int = 64) -> bytes:
    segment = tcp(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload)
    return ethernet(src_mac, dst_mac, ipv4(src_ip, dst_ip, 6, segment, ttl=ttl))


def raw_tcp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, seq: int,
                   ack: int, flags: int, payload: bytes = b"", *, ttl: int = 64) -> bytes:
    return ipv4(src_ip, dst_ip, 6, tcp(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload), ttl=ttl)


def udp_frame(src_mac: str, dst_mac: str, src_ip: str, dst_ip: str, src_port: int,
              dst_port: int, payload: bytes, *, ttl: int = 64) -> bytes:
    datagram = udp(src_ip, dst_ip, src_port, dst_port, payload)
    return ethernet(src_mac, dst_mac, ipv4(src_ip, dst_ip, 17, datagram, ttl=ttl))


def arp_packet(src_mac: str, src_ip: str, target_mac: str, target_ip: str,
               *, operation: int, ethernet_dst: str) -> bytes:
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        1,
        0x0800,
        6,
        4,
        operation,
        mac_bytes(src_mac),
        ip_bytes(src_ip),
        mac_bytes(target_mac),
        ip_bytes(target_ip),
    )
    return ethernet(src_mac, ethernet_dst, arp, 0x0806)


def arp_request(src_mac: str, src_ip: str, target_ip: str) -> bytes:
    return arp_packet(src_mac, src_ip, "00:00:00:00:00:00", target_ip,
                      operation=1, ethernet_dst="ff:ff:ff:ff:ff:ff")


def arp_reply(src_mac: str, src_ip: str, target_mac: str, target_ip: str) -> bytes:
    return arp_packet(src_mac, src_ip, target_mac, target_ip,
                      operation=2, ethernet_dst=target_mac)


def encode_dns_name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\x00"


def dns_query(name: str, transaction_id: int) -> bytes:
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    return header + encode_dns_name(name) + struct.pack("!HH", 1, 1)


def dns_response(name: str, address: str, transaction_id: int) -> bytes:
    question = encode_dns_name(name) + struct.pack("!HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + ip_bytes(address)
    header = struct.pack("!HHHHHH", transaction_id, 0x8180, 1, 1, 0, 0)
    return header + question + answer


def icmp_echo(identifier: int, sequence: int, payload: bytes, *, reply: bool = False) -> bytes:
    icmp_type = 0 if reply else 8
    body = struct.pack("!BBHHH", icmp_type, 0, 0, identifier, sequence) + payload
    return body[:2] + struct.pack("!H", checksum(body)) + body[4:]


def icmp_time_exceeded(original_ip_and_8: bytes) -> bytes:
    body = struct.pack("!BBHI", 11, 0, 0, 0) + original_ip_and_8
    return body[:2] + struct.pack("!H", checksum(body)) + body[4:]


def icmp_frame(src_mac: str, dst_mac: str, src_ip: str, dst_ip: str, message: bytes,
               *, ttl: int = 64) -> bytes:
    return ethernet(src_mac, dst_mac, ipv4(src_ip, dst_ip, 1, message, ttl=ttl))


@dataclass
class Capture:
    name: str
    linktype: int = LINKTYPE_ETHERNET
    base_offset: float = 0.0
    packets: list[tuple[float, bytes]] = field(default_factory=list)

    def add(self, offset: float, packet: bytes) -> None:
        self.packets.append((BASE_EPOCH + self.base_offset + offset, packet))

    def write(self, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / self.name
        with path.open("wb") as stream:
            stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, self.linktype))
            for timestamp, packet in sorted(self.packets, key=lambda item: item[0]):
                seconds = int(timestamp)
                micros = int(round((timestamp - seconds) * 1_000_000))
                if micros == 1_000_000:
                    seconds += 1
                    micros = 0
                stream.write(struct.pack("<IIII", seconds, micros, len(packet), len(packet)))
                stream.write(packet)
        return path


def lab_01() -> tuple[Capture, Capture]:
    client = ("10.10.10.25", "02:00:00:00:10:25")
    server = ("10.10.10.50", "02:00:00:00:10:50")
    dns = ("10.10.10.53", "02:00:00:00:10:53")
    cap = Capture("01a_direction_ports_and_display_filters.pcap", base_offset=0)

    cap.add(0.000, arp_request(client[1], client[0], server[0]))
    cap.add(0.002, arp_reply(server[1], server[0], client[1], client[0]))
    cap.add(0.010, udp_frame(client[1], dns[1], client[0], dns[0], 53000, 53,
                             dns_query("portal.training.test", 0x1001)))
    cap.add(0.018, udp_frame(dns[1], client[1], dns[0], client[0], 53, 53000,
                             dns_response("portal.training.test", server[0], 0x1001)))

    cseq, sseq = 10_000, 50_000
    request = b"GET /status HTTP/1.1\r\nHost: portal.training.test\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
    cap.add(0.030, tcp_frame(client[1], server[1], client[0], server[0], 51000, 80, cseq, 0, TCP_SYN))
    cap.add(0.034, tcp_frame(server[1], client[1], server[0], client[0], 80, 51000, sseq, cseq + 1, TCP_SYN | TCP_ACK))
    cap.add(0.036, tcp_frame(client[1], server[1], client[0], server[0], 51000, 80, cseq + 1, sseq + 1, TCP_ACK))
    cap.add(0.040, tcp_frame(client[1], server[1], client[0], server[0], 51000, 80, cseq + 1, sseq + 1, TCP_PSH | TCP_ACK, request))
    cap.add(0.043, tcp_frame(server[1], client[1], server[0], client[0], 80, 51000, sseq + 1, cseq + 1 + len(request), TCP_ACK))
    cap.add(0.050, tcp_frame(server[1], client[1], server[0], client[0], 80, 51000, sseq + 1, cseq + 1 + len(request), TCP_PSH | TCP_ACK, response))
    cap.add(0.053, tcp_frame(client[1], server[1], client[0], server[0], 51000, 80, cseq + 1 + len(request), sseq + 1 + len(response), TCP_ACK))
    cap.add(0.060, tcp_frame(server[1], client[1], server[0], client[0], 80, 51000, sseq + 1 + len(response), cseq + 1 + len(request), TCP_FIN | TCP_ACK))
    cap.add(0.062, tcp_frame(client[1], server[1], client[0], server[0], 51000, 80, cseq + 1 + len(request), sseq + 2 + len(response), TCP_ACK))
    cap.add(0.070, tcp_frame(client[1], server[1], client[0], server[0], 51000, 80, cseq + 1 + len(request), sseq + 2 + len(response), TCP_FIN | TCP_ACK))
    cap.add(0.073, tcp_frame(server[1], client[1], server[0], client[0], 80, 51000, sseq + 2 + len(response), cseq + 2 + len(request), TCP_ACK))

    tcp_only = Capture("01b_tcp_capture_filter_simulation.pcap", base_offset=0)
    for ts, packet in cap.packets:
        if packet[12:14] == b"\x08\x00" and len(packet) >= 24 and packet[23] == 6:
            tcp_only.packets.append((ts, packet))
    return cap, tcp_only


def lab_02() -> Capture:
    client = ("192.168.56.10", "02:00:00:00:56:10")
    server = ("192.168.56.20", "02:00:00:00:56:20")
    cap = Capture("02_tcp_outcomes_payload_and_closure.pcap", base_offset=60)

    # Open SSH-like service with ACK-only data and FIN carrying final data.
    cseq, sseq = 1_000, 8_000
    client_data = b"SSH-2.0-TrainingClient\r\n"
    final_data = b"session-final-data"
    cap.add(0.000, tcp_frame(client[1], server[1], client[0], server[0], 52000, 22, cseq, 0, TCP_SYN))
    cap.add(0.004, tcp_frame(server[1], client[1], server[0], client[0], 22, 52000, sseq, cseq + 1, TCP_SYN | TCP_ACK))
    cap.add(0.006, tcp_frame(client[1], server[1], client[0], server[0], 52000, 22, cseq + 1, sseq + 1, TCP_ACK))
    cap.add(0.010, tcp_frame(client[1], server[1], client[0], server[0], 52000, 22, cseq + 1, sseq + 1, TCP_ACK, client_data))
    cap.add(0.013, tcp_frame(server[1], client[1], server[0], client[0], 22, 52000, sseq + 1, cseq + 1 + len(client_data), TCP_ACK))
    cap.add(0.020, tcp_frame(server[1], client[1], server[0], client[0], 22, 52000, sseq + 1, cseq + 1 + len(client_data), TCP_FIN | TCP_ACK, final_data))
    cap.add(0.023, tcp_frame(client[1], server[1], client[0], server[0], 52000, 22, cseq + 1 + len(client_data), sseq + 2 + len(final_data), TCP_ACK))
    cap.add(0.030, tcp_frame(client[1], server[1], client[0], server[0], 52000, 22, cseq + 1 + len(client_data), sseq + 2 + len(final_data), TCP_FIN | TCP_ACK))
    cap.add(0.033, tcp_frame(server[1], client[1], server[0], client[0], 22, 52000, sseq + 2 + len(final_data), cseq + 2 + len(client_data), TCP_ACK))

    # Closed Telnet-like port.
    cap.add(1.000, tcp_frame(client[1], server[1], client[0], server[0], 52001, 23, 2_000, 0, TCP_SYN))
    cap.add(1.004, tcp_frame(server[1], client[1], server[0], client[0], 23, 52001, 0, 2_001, TCP_RST | TCP_ACK))

    # No response: the repeated SYNs support several explanations, not a definitive closed state.
    cap.add(2.000, tcp_frame(client[1], server[1], client[0], server[0], 52002, 445, 3_000, 0, TCP_SYN))
    cap.add(3.000, tcp_frame(client[1], server[1], client[0], server[0], 52002, 445, 3_000, 0, TCP_SYN))
    cap.add(5.000, tcp_frame(client[1], server[1], client[0], server[0], 52002, 445, 3_000, 0, TCP_SYN))

    # Established application flow abruptly reset; the RST also has payload.
    cseq, sseq = 4_000, 12_000
    app_data = b"COMMAND status\n"
    reset_data = b"ABORT-NOT-RELIABLE"
    cap.add(6.000, tcp_frame(client[1], server[1], client[0], server[0], 52003, 8080, cseq, 0, TCP_SYN))
    cap.add(6.004, tcp_frame(server[1], client[1], server[0], client[0], 8080, 52003, sseq, cseq + 1, TCP_SYN | TCP_ACK))
    cap.add(6.006, tcp_frame(client[1], server[1], client[0], server[0], 52003, 8080, cseq + 1, sseq + 1, TCP_ACK))
    cap.add(6.010, tcp_frame(client[1], server[1], client[0], server[0], 52003, 8080, cseq + 1, sseq + 1, TCP_PSH | TCP_ACK, app_data))
    cap.add(6.014, tcp_frame(server[1], client[1], server[0], client[0], 8080, 52003, sseq + 1, cseq + 1 + len(app_data), TCP_RST | TCP_ACK, reset_data))
    return cap


def lab_03() -> Capture:
    client = ("172.16.5.10", "02:00:00:00:05:10")
    server = ("172.16.5.20", "02:00:00:00:05:20")
    cap = Capture("03_retransmission_duplicate_acks_and_fast_recovery.pcap", base_offset=120)

    # Flow 1: three duplicate ACKs followed by a fast retransmission.
    cseq, sseq = 1_000, 9_000
    cap.add(0.000, tcp_frame(client[1], server[1], client[0], server[0], 53000, 9000, cseq, 0, TCP_SYN))
    cap.add(0.003, tcp_frame(server[1], client[1], server[0], client[0], 9000, 53000, sseq, cseq + 1, TCP_SYN | TCP_ACK))
    cap.add(0.005, tcp_frame(client[1], server[1], client[0], server[0], 53000, 9000, cseq + 1, sseq + 1, TCP_ACK))
    cap.add(0.010, tcp_frame(client[1], server[1], client[0], server[0], 53000, 9000, 1_001, 9_001, TCP_ACK, b"A" * 100))
    cap.add(0.013, tcp_frame(server[1], client[1], server[0], client[0], 9000, 53000, 9_001, 1_101, TCP_ACK))
    cap.add(0.018, tcp_frame(client[1], server[1], client[0], server[0], 53000, 9000, 1_101, 9_001, TCP_ACK, b"B" * 100))
    cap.add(0.020, tcp_frame(client[1], server[1], client[0], server[0], 53000, 9000, 1_201, 9_001, TCP_ACK, b"C" * 100))
    cap.add(0.023, tcp_frame(server[1], client[1], server[0], client[0], 9000, 53000, 9_001, 1_101, TCP_ACK))
    cap.add(0.026, tcp_frame(client[1], server[1], client[0], server[0], 53000, 9000, 1_301, 9_001, TCP_ACK, b"D" * 100))
    cap.add(0.029, tcp_frame(server[1], client[1], server[0], client[0], 9000, 53000, 9_001, 1_101, TCP_ACK))
    cap.add(0.032, tcp_frame(client[1], server[1], client[0], server[0], 53000, 9000, 1_401, 9_001, TCP_ACK, b"E" * 100))
    cap.add(0.035, tcp_frame(server[1], client[1], server[0], client[0], 9000, 53000, 9_001, 1_101, TCP_ACK))
    cap.add(0.038, tcp_frame(client[1], server[1], client[0], server[0], 53000, 9000, 1_101, 9_001, TCP_ACK, b"B" * 100))
    cap.add(0.042, tcp_frame(server[1], client[1], server[0], client[0], 9000, 53000, 9_001, 1_501, TCP_ACK))

    # Flow 2: timeout-style retransmission after no ACK is observed.
    cseq, sseq = 3_000, 15_000
    cap.add(1.000, tcp_frame(client[1], server[1], client[0], server[0], 53001, 9001, cseq, 0, TCP_SYN))
    cap.add(1.003, tcp_frame(server[1], client[1], server[0], client[0], 9001, 53001, sseq, cseq + 1, TCP_SYN | TCP_ACK))
    cap.add(1.005, tcp_frame(client[1], server[1], client[0], server[0], 53001, 9001, cseq + 1, sseq + 1, TCP_ACK))
    cap.add(1.010, tcp_frame(client[1], server[1], client[0], server[0], 53001, 9001, cseq + 1, sseq + 1, TCP_PSH | TCP_ACK, b"T" * 80))
    cap.add(2.210, tcp_frame(client[1], server[1], client[0], server[0], 53001, 9001, cseq + 1, sseq + 1, TCP_PSH | TCP_ACK, b"T" * 80))
    cap.add(2.214, tcp_frame(server[1], client[1], server[0], client[0], 9001, 53001, sseq + 1, cseq + 1 + 80, TCP_ACK))
    return cap


def lab_04() -> Capture:
    scanner_v = ("10.0.0.5", "02:00:00:00:00:05")
    scanner_h = ("10.0.0.6", "02:00:00:00:00:06")
    scanner_b = ("10.0.0.7", "02:00:00:00:00:07")
    target_mac = "02:00:00:00:00:14"
    cap = Capture("04_vertical_horizontal_and_half_open_scans.pcap", base_offset=180)

    # Vertical scan: one target, changing destination ports.
    target_ip = "10.0.0.20"
    specs = [
        (21, "closed"),
        (22, "open"),
        (23, "silent"),
        (80, "open"),
        (443, "closed"),
    ]
    t = 0.000
    for index, (port, state) in enumerate(specs):
        sport = 40000 + index
        seq = 1_000 + index * 100
        cap.add(t, tcp_frame(scanner_v[1], target_mac, scanner_v[0], target_ip, sport, port, seq, 0, TCP_SYN))
        if state == "closed":
            cap.add(t + 0.003, tcp_frame(target_mac, scanner_v[1], target_ip, scanner_v[0], port, sport, 0, seq + 1, TCP_RST | TCP_ACK))
        elif state == "open":
            sseq = 9_000 + index * 100
            cap.add(t + 0.003, tcp_frame(target_mac, scanner_v[1], target_ip, scanner_v[0], port, sport, sseq, seq + 1, TCP_SYN | TCP_ACK))
            cap.add(t + 0.005, tcp_frame(scanner_v[1], target_mac, scanner_v[0], target_ip, sport, port, seq + 1, sseq + 1, TCP_RST))
        t += 0.020

    # Horizontal scan: one port, changing destination hosts.
    t = 1.000
    states = ["closed", "silent", "open", "closed", "open"]
    for index, host in enumerate(range(20, 25)):
        dst_ip = f"10.0.0.{host}"
        dst_mac = f"02:00:00:00:00:{host:02x}"
        sport = 41000 + index
        seq = 2_000 + index * 100
        cap.add(t, tcp_frame(scanner_h[1], dst_mac, scanner_h[0], dst_ip, sport, 445, seq, 0, TCP_SYN))
        if states[index] == "closed":
            cap.add(t + 0.003, tcp_frame(dst_mac, scanner_h[1], dst_ip, scanner_h[0], 445, sport, 0, seq + 1, TCP_RST | TCP_ACK))
        elif states[index] == "open":
            sseq = 12_000 + index * 100
            cap.add(t + 0.003, tcp_frame(dst_mac, scanner_h[1], dst_ip, scanner_h[0], 445, sport, sseq, seq + 1, TCP_SYN | TCP_ACK))
            cap.add(t + 0.005, tcp_frame(scanner_h[1], dst_mac, scanner_h[0], dst_ip, sport, 445, seq + 1, sseq + 1, TCP_RST))
        t += 0.020

    # Broader discovery: both hosts and ports change.
    t = 2.000
    broad = [(30, 22, "closed"), (31, 80, "open"), (32, 443, "silent"),
             (33, 3389, "closed"), (34, 8080, "open"), (35, 53, "silent")]
    for index, (host, port, state) in enumerate(broad):
        dst_ip = f"10.0.0.{host}"
        dst_mac = f"02:00:00:00:00:{host:02x}"
        sport = 42000 + index
        seq = 3_000 + index * 100
        cap.add(t, tcp_frame(scanner_b[1], dst_mac, scanner_b[0], dst_ip, sport, port, seq, 0, TCP_SYN))
        if state == "closed":
            cap.add(t + 0.003, tcp_frame(dst_mac, scanner_b[1], dst_ip, scanner_b[0], port, sport, 0, seq + 1, TCP_RST | TCP_ACK))
        elif state == "open":
            sseq = 15_000 + index * 100
            cap.add(t + 0.003, tcp_frame(dst_mac, scanner_b[1], dst_ip, scanner_b[0], port, sport, sseq, seq + 1, TCP_SYN | TCP_ACK))
            cap.add(t + 0.005, tcp_frame(scanner_b[1], dst_mac, scanner_b[0], dst_ip, sport, port, seq + 1, sseq + 1, TCP_RST))
        t += 0.020
    return cap


def lab_05() -> Capture:
    victim = ("192.168.1.10", "02:00:00:00:01:10")
    peer = ("192.168.1.50", "02:00:00:00:01:50")
    gateway = ("192.168.1.1", "00:11:22:33:44:55")
    attacker = ("192.168.1.66", "66:66:66:66:66:66")
    remote_ip = "203.0.113.80"
    cap = Capture("05_ethernet_arp_gateway_and_spoofing.pcap", base_offset=240)

    cap.add(0.000, arp_request(victim[1], victim[0], peer[0]))
    cap.add(0.003, arp_reply(peer[1], peer[0], victim[1], victim[0]))
    cap.add(0.010, tcp_frame(victim[1], peer[1], victim[0], peer[0], 54000, 22, 1_000, 0, TCP_SYN))
    cap.add(0.013, tcp_frame(peer[1], victim[1], peer[0], victim[0], 22, 54000, 0, 1_001, TCP_RST | TCP_ACK))

    cap.add(0.100, arp_request(victim[1], victim[0], gateway[0]))
    cap.add(0.103, arp_reply(gateway[1], gateway[0], victim[1], victim[0]))
    cap.add(0.110, tcp_frame(victim[1], gateway[1], victim[0], remote_ip, 54001, 443, 2_000, 0, TCP_SYN))
    cap.add(0.140, tcp_frame(gateway[1], victim[1], remote_ip, victim[0], 443, 54001, 8_000, 2_001, TCP_SYN | TCP_ACK, ttl=58))
    cap.add(0.143, tcp_frame(victim[1], gateway[1], victim[0], remote_ip, 54001, 443, 2_001, 8_001, TCP_ACK))

    # Conflicting claims for the gateway IP.
    cap.add(1.000, arp_reply(gateway[1], gateway[0], victim[1], victim[0]))
    cap.add(1.100, arp_reply(attacker[1], gateway[0], victim[1], victim[0]))
    payload = b"encrypted-looking-training-bytes"
    cap.add(1.200, tcp_frame(victim[1], attacker[1], victim[0], remote_ip, 54001, 443, 2_001, 8_001, TCP_PSH | TCP_ACK, payload))
    cap.add(1.202, tcp_frame(attacker[1], gateway[1], victim[0], remote_ip, 54001, 443, 2_001, 8_001, TCP_PSH | TCP_ACK, payload))
    reply = b"remote-response"
    cap.add(1.240, tcp_frame(gateway[1], attacker[1], remote_ip, victim[0], 443, 54001, 8_001, 2_001 + len(payload), TCP_PSH | TCP_ACK, reply, ttl=58))
    cap.add(1.242, tcp_frame(attacker[1], victim[1], remote_ip, victim[0], 443, 54001, 8_001, 2_001 + len(payload), TCP_PSH | TCP_ACK, reply, ttl=58))
    cap.add(1.500, arp_reply(gateway[1], gateway[0], victim[1], victim[0]))
    cap.add(1.600, arp_reply(attacker[1], gateway[0], victim[1], victim[0]))
    cap.add(1.700, tcp_frame(victim[1], attacker[1], victim[0], remote_ip, 54001, 443, 2_001 + len(payload), 8_001 + len(reply), TCP_ACK))

    cap.add(2.000, arp_request(victim[1], victim[0], gateway[0]))
    cap.add(2.003, arp_reply(gateway[1], gateway[0], victim[1], victim[0]))
    cap.add(2.006, arp_reply(attacker[1], gateway[0], victim[1], victim[0]))
    return cap


def lab_06() -> Capture:
    host = ("172.16.5.10", "02:00:00:00:05:10")
    peer = ("172.16.5.20", "02:00:00:00:05:20")
    gateway = ("172.16.5.1", "02:00:00:00:05:01")
    remote_private = "172.16.6.20"
    public = "198.51.100.25"
    cap = Capture("06_subnets_gateway_choices_and_ttl.pcap", base_offset=300)

    cap.add(0.000, arp_request(host[1], host[0], peer[0]))
    cap.add(0.003, arp_reply(peer[1], peer[0], host[1], host[0]))
    cap.add(0.010, tcp_frame(host[1], peer[1], host[0], peer[0], 55000, 80, 1_000, 0, TCP_SYN, ttl=64))
    cap.add(0.013, tcp_frame(peer[1], host[1], peer[0], host[0], 80, 55000, 0, 1_001, TCP_RST | TCP_ACK, ttl=64))

    cap.add(0.100, arp_request(host[1], host[0], gateway[0]))
    cap.add(0.103, arp_reply(gateway[1], gateway[0], host[1], host[0]))
    cap.add(0.110, tcp_frame(host[1], gateway[1], host[0], remote_private, 55001, 443, 2_000, 0, TCP_SYN, ttl=64))
    cap.add(0.140, tcp_frame(gateway[1], host[1], remote_private, host[0], 443, 55001, 8_000, 2_001, TCP_SYN | TCP_ACK, ttl=58))
    cap.add(0.143, tcp_frame(host[1], gateway[1], host[0], remote_private, 55001, 443, 2_001, 8_001, TCP_ACK, ttl=64))

    cap.add(0.200, tcp_frame(host[1], gateway[1], host[0], public, 55002, 443, 3_000, 0, TCP_SYN, ttl=64))
    cap.add(0.240, tcp_frame(gateway[1], host[1], public, host[0], 443, 55002, 12_000, 3_001, TCP_SYN | TCP_ACK, ttl=117))
    cap.add(0.243, tcp_frame(host[1], gateway[1], host[0], public, 55002, 443, 3_001, 12_001, TCP_ACK, ttl=64))

    echo_low = icmp_echo(0x2222, 1, b"low-ttl-training")
    original_low = ipv4(host[0], public, 1, echo_low, ttl=2, identification=0x6001)
    cap.add(1.000, ethernet(host[1], gateway[1], original_low))
    exceeded = icmp_time_exceeded(original_low[:28])
    cap.add(1.030, icmp_frame(gateway[1], host[1], gateway[0], host[0], exceeded, ttl=64))

    echo_nine = icmp_echo(0x2222, 2, b"ttl-nine-training")
    cap.add(1.100, icmp_frame(host[1], gateway[1], host[0], public, echo_nine, ttl=9))
    echo_reply = icmp_echo(0x2222, 2, b"ttl-nine-training", reply=True)
    cap.add(1.150, icmp_frame(gateway[1], host[1], public, host[0], echo_reply, ttl=58))

    cap.add(1.200, udp_frame(gateway[1], host[1], "203.0.113.99", host[0], 9999, 56000,
                             b"observed-with-high-ttl", ttl=243))
    return cap


def lab_07() -> Capture:
    cap = Capture("07_loopback_localhost_raw_ipv4.pcap", linktype=LINKTYPE_RAW_IPV4, base_offset=360)
    src = dst = "127.0.0.1"
    cseq, sseq = 1_000, 5_000
    request = b"local request"
    response = b"local response"
    cap.add(0.000, raw_tcp_packet(src, dst, 55000, 3000, cseq, 0, TCP_SYN))
    cap.add(0.001, raw_tcp_packet(src, dst, 3000, 55000, sseq, cseq + 1, TCP_SYN | TCP_ACK))
    cap.add(0.002, raw_tcp_packet(src, dst, 55000, 3000, cseq + 1, sseq + 1, TCP_ACK))
    cap.add(0.003, raw_tcp_packet(src, dst, 55000, 3000, cseq + 1, sseq + 1, TCP_PSH | TCP_ACK, request))
    cap.add(0.004, raw_tcp_packet(src, dst, 3000, 55000, sseq + 1, cseq + 1 + len(request), TCP_ACK))
    cap.add(0.005, raw_tcp_packet(src, dst, 3000, 55000, sseq + 1, cseq + 1 + len(request), TCP_PSH | TCP_ACK, response))
    cap.add(0.006, raw_tcp_packet(src, dst, 55000, 3000, cseq + 1 + len(request), sseq + 1 + len(response), TCP_ACK))
    cap.add(0.010, raw_tcp_packet(src, dst, 55000, 3000, cseq + 1 + len(request), sseq + 1 + len(response), TCP_FIN | TCP_ACK))
    cap.add(0.011, raw_tcp_packet(src, dst, 3000, 55000, sseq + 1 + len(response), cseq + 2 + len(request), TCP_ACK))
    cap.add(0.012, raw_tcp_packet(src, dst, 3000, 55000, sseq + 1 + len(response), cseq + 2 + len(request), TCP_FIN | TCP_ACK))
    cap.add(0.013, raw_tcp_packet(src, dst, 55000, 3000, cseq + 2 + len(request), sseq + 2 + len(response), TCP_ACK))
    return cap


def lab_08() -> Capture:
    user = ("10.20.30.25", "02:20:30:00:00:25")
    web = ("10.20.30.40", "02:20:30:00:00:40")
    dns = ("10.20.30.53", "02:20:30:00:00:53")
    gateway = ("10.20.30.1", "02:20:30:00:00:01")
    suspicious = ("10.20.30.77", "02:20:30:00:00:77")
    remote = "203.0.113.50"
    cap = Capture("08_mixed_soc_challenge.pcap", base_offset=420)

    cap.add(0.000, udp_frame(user[1], dns[1], user[0], dns[0], 57000, 53,
                             dns_query("updates.training.test", 0x8080)))
    cap.add(0.008, udp_frame(dns[1], user[1], dns[0], user[0], 53, 57000,
                             dns_response("updates.training.test", web[0], 0x8080)))

    # Normal HTTP flow.
    cseq, sseq = 1_000, 8_000
    req = b"GET /health HTTP/1.1\r\nHost: updates.training.test\r\n\r\n"
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nhealthy"
    cap.add(0.020, tcp_frame(user[1], web[1], user[0], web[0], 57001, 80, cseq, 0, TCP_SYN))
    cap.add(0.023, tcp_frame(web[1], user[1], web[0], user[0], 80, 57001, sseq, cseq + 1, TCP_SYN | TCP_ACK))
    cap.add(0.025, tcp_frame(user[1], web[1], user[0], web[0], 57001, 80, cseq + 1, sseq + 1, TCP_ACK))
    cap.add(0.030, tcp_frame(user[1], web[1], user[0], web[0], 57001, 80, cseq + 1, sseq + 1, TCP_PSH | TCP_ACK, req))
    cap.add(0.033, tcp_frame(web[1], user[1], web[0], user[0], 80, 57001, sseq + 1, cseq + 1 + len(req), TCP_ACK))
    cap.add(0.038, tcp_frame(web[1], user[1], web[0], user[0], 80, 57001, sseq + 1, cseq + 1 + len(req), TCP_PSH | TCP_ACK, resp))
    cap.add(0.041, tcp_frame(user[1], web[1], user[0], web[0], 57001, 80, cseq + 1 + len(req), sseq + 1 + len(resp), TCP_ACK))
    cap.add(0.050, tcp_frame(web[1], user[1], web[0], user[0], 80, 57001, sseq + 1 + len(resp), cseq + 1 + len(req), TCP_FIN | TCP_ACK))
    cap.add(0.052, tcp_frame(user[1], web[1], user[0], web[0], 57001, 80, cseq + 1 + len(req), sseq + 2 + len(resp), TCP_ACK))
    cap.add(0.055, tcp_frame(user[1], web[1], user[0], web[0], 57001, 80, cseq + 1 + len(req), sseq + 2 + len(resp), TCP_FIN | TCP_ACK))
    cap.add(0.058, tcp_frame(web[1], user[1], web[0], user[0], 80, 57001, sseq + 2 + len(resp), cseq + 2 + len(req), TCP_ACK))

    # Closed service.
    cap.add(0.200, tcp_frame(user[1], web[1], user[0], web[0], 57002, 3389, 3_000, 0, TCP_SYN))
    cap.add(0.203, tcp_frame(web[1], user[1], web[0], user[0], 3389, 57002, 0, 3_001, TCP_RST | TCP_ACK))

    # Vertical, mostly half-open scan from .77 to .40.
    t = 1.000
    scan_states = [(21, "closed"), (22, "open"), (23, "silent"),
                   (80, "open"), (443, "closed"), (445, "silent")]
    for index, (port, state) in enumerate(scan_states):
        sport, seq = 58000 + index, 5_000 + index * 100
        cap.add(t, tcp_frame(suspicious[1], web[1], suspicious[0], web[0], sport, port, seq, 0, TCP_SYN))
        if state == "closed":
            cap.add(t + 0.003, tcp_frame(web[1], suspicious[1], web[0], suspicious[0], port, sport, 0, seq + 1, TCP_RST | TCP_ACK))
        elif state == "open":
            server_seq = 20_000 + index * 100
            cap.add(t + 0.003, tcp_frame(web[1], suspicious[1], web[0], suspicious[0], port, sport, server_seq, seq + 1, TCP_SYN | TCP_ACK))
            cap.add(t + 0.005, tcp_frame(suspicious[1], web[1], suspicious[0], web[0], sport, port, seq + 1, server_seq + 1, TCP_RST))
        t += 0.020

    # Normal remote connection uses gateway MAC while retaining remote IP.
    cap.add(2.000, tcp_frame(user[1], gateway[1], user[0], remote, 57003, 443, 7_000, 0, TCP_SYN))
    cap.add(2.030, tcp_frame(gateway[1], user[1], remote, user[0], 443, 57003, 30_000, 7_001, TCP_SYN | TCP_ACK, ttl=58))
    cap.add(2.033, tcp_frame(user[1], gateway[1], user[0], remote, 57003, 443, 7_001, 30_001, TCP_ACK))

    # Competing gateway claims and a resulting Ethernet destination change.
    cap.add(2.100, arp_reply(gateway[1], gateway[0], user[1], user[0]))
    cap.add(2.200, arp_reply(suspicious[1], gateway[0], user[1], user[0]))
    cap.add(2.250, tcp_frame(user[1], suspicious[1], user[0], remote, 57003, 443, 7_001, 30_001, TCP_ACK, b"challenge-data"))
    cap.add(2.300, arp_reply(gateway[1], gateway[0], user[1], user[0]))
    cap.add(2.400, arp_reply(suspicious[1], gateway[0], user[1], user[0]))

    # Ordinary retransmission on another service.
    cseq, sseq = 9_000, 40_000
    cap.add(3.000, tcp_frame(user[1], web[1], user[0], web[0], 57004, 9001, cseq, 0, TCP_SYN))
    cap.add(3.003, tcp_frame(web[1], user[1], web[0], user[0], 9001, 57004, sseq, cseq + 1, TCP_SYN | TCP_ACK))
    cap.add(3.005, tcp_frame(user[1], web[1], user[0], web[0], 57004, 9001, cseq + 1, sseq + 1, TCP_ACK))
    cap.add(3.010, tcp_frame(user[1], web[1], user[0], web[0], 57004, 9001, cseq + 1, sseq + 1, TCP_PSH | TCP_ACK, b"R" * 64))
    cap.add(4.210, tcp_frame(user[1], web[1], user[0], web[0], 57004, 9001, cseq + 1, sseq + 1, TCP_PSH | TCP_ACK, b"R" * 64))
    cap.add(4.214, tcp_frame(web[1], user[1], web[0], user[0], 9001, 57004, sseq + 1, cseq + 1 + 64, TCP_ACK))

    low = icmp_echo(0x8888, 1, b"challenge-low-ttl")
    original = ipv4(user[0], remote, 1, low, ttl=2, identification=0x8801)
    cap.add(5.000, ethernet(user[1], gateway[1], original))
    cap.add(5.030, icmp_frame(gateway[1], user[1], gateway[0], user[0],
                              icmp_time_exceeded(original[:28]), ttl=64))
    return cap


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    output_dir = root / "captures"
    lab1_full, lab1_tcp = lab_01()
    captures = [lab1_full, lab1_tcp, lab_02(), lab_03(), lab_04(), lab_05(), lab_06(), lab_07(), lab_08()]
    rows = []
    for capture in captures:
        path = capture.write(output_dir)
        rows.append((path.name, len(capture.packets), capture.linktype, path.stat().st_size))

    manifest = root / "CAPTURE_MANIFEST.tsv"
    manifest.write_text(
        "file\tpackets\tlinktype\tbytes\n" +
        "\n".join(f"{name}\t{count}\t{linktype}\t{size}" for name, count, linktype, size in rows) +
        "\n",
        encoding="utf-8",
    )
    for name, count, linktype, size in rows:
        print(f"{name}: {count} packets, linktype {linktype}, {size} bytes")


if __name__ == "__main__":
    main()
