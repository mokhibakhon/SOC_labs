#!/usr/bin/env python3
"""Structural and checksum validation for the included synthetic PCAP files."""

from __future__ import annotations

import struct
from pathlib import Path


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def validate_ipv4(packet: bytes, label: str) -> None:
    assert len(packet) >= 20, f"{label}: truncated IPv4 header"
    ihl = (packet[0] & 0x0F) * 4
    total_length = struct.unpack("!H", packet[2:4])[0]
    assert packet[0] >> 4 == 4, f"{label}: not IPv4"
    assert ihl >= 20 and total_length >= ihl, f"{label}: invalid IPv4 lengths"
    assert len(packet) >= total_length, f"{label}: truncated IPv4 packet"
    assert checksum(packet[:ihl]) == 0, f"{label}: invalid IPv4 header checksum"

    protocol = packet[9]
    src, dst = packet[12:16], packet[16:20]
    transport = packet[ihl:total_length]
    if protocol == 6:
        assert len(transport) >= 20, f"{label}: truncated TCP header"
        pseudo = src + dst + struct.pack("!BBH", 0, 6, len(transport))
        assert checksum(pseudo + transport) == 0, f"{label}: invalid TCP checksum"
    elif protocol == 17:
        assert len(transport) >= 8, f"{label}: truncated UDP header"
        udp_length = struct.unpack("!H", transport[4:6])[0]
        assert udp_length == len(transport), f"{label}: invalid UDP length"
        pseudo = src + dst + struct.pack("!BBH", 0, 17, len(transport))
        assert checksum(pseudo + transport) == 0, f"{label}: invalid UDP checksum"
    elif protocol == 1:
        assert len(transport) >= 8, f"{label}: truncated ICMP message"
        assert checksum(transport) == 0, f"{label}: invalid ICMP checksum"


def validate_file(path: Path) -> tuple[int, int]:
    data = path.read_bytes()
    assert len(data) >= 24, f"{path.name}: truncated global header"
    magic, major, minor, _, _, snaplen, linktype = struct.unpack("<IHHIIII", data[:24])
    assert magic == 0xA1B2C3D4, f"{path.name}: unsupported magic"
    assert (major, minor) == (2, 4), f"{path.name}: unexpected PCAP version"
    assert snaplen >= 65535, f"{path.name}: snap length too small"
    assert linktype in (1, 101), f"{path.name}: unexpected link type"

    offset = 24
    count = 0
    previous_timestamp = -1
    while offset < len(data):
        assert offset + 16 <= len(data), f"{path.name}: truncated record header"
        sec, usec, captured, original = struct.unpack("<IIII", data[offset:offset + 16])
        offset += 16
        assert captured == original, f"{path.name}: unexpected truncation"
        assert offset + captured <= len(data), f"{path.name}: truncated record data"
        packet = data[offset:offset + captured]
        offset += captured
        count += 1
        timestamp = sec * 1_000_000 + usec
        assert timestamp >= previous_timestamp, f"{path.name}: timestamps out of order"
        previous_timestamp = timestamp

        label = f"{path.name} packet {count}"
        if linktype == 1:
            assert len(packet) >= 14, f"{label}: truncated Ethernet frame"
            ethertype = struct.unpack("!H", packet[12:14])[0]
            if ethertype == 0x0800:
                validate_ipv4(packet[14:], label)
            elif ethertype == 0x0806:
                assert len(packet) >= 42, f"{label}: truncated ARP packet"
                assert packet[14:22] == b"\x00\x01\x08\x00\x06\x04\x00\x01" or packet[14:22] == b"\x00\x01\x08\x00\x06\x04\x00\x02", f"{label}: malformed ARP header"
            else:
                raise AssertionError(f"{label}: unexpected EtherType 0x{ethertype:04x}")
        else:
            validate_ipv4(packet, label)

    assert offset == len(data), f"{path.name}: trailing bytes"
    assert count > 0, f"{path.name}: empty capture"
    return count, linktype


def main() -> None:
    capture_dir = Path(__file__).resolve().parents[1] / "captures"
    files = sorted(capture_dir.glob("*.pcap"))
    assert files, "No PCAP files found"
    total = 0
    for path in files:
        count, linktype = validate_file(path)
        total += count
        print(f"PASS  {path.name}: {count} packets, linktype {linktype}")
    print(f"PASS  all {len(files)} files ({total} packets)")


if __name__ == "__main__":
    main()
