# Wireshark Filter Cheat Sheet

## Display filters

These filters change what is visible without deleting captured packets.

| Goal | Display filter |
| --- | --- |
| All TCP | `tcp` |
| All UDP | `udp` |
| All ARP | `arp` |
| All DNS | `dns` |
| All ICMP | `icmp` |
| Either direction for an IP | `ip.addr == 10.0.0.5` |
| Source IP only | `ip.src == 10.0.0.5` |
| Destination IP only | `ip.dst == 10.0.0.20` |
| Either TCP port | `tcp.port == 443` |
| Destination TCP port | `tcp.dstport == 443` |
| UDP requests to DNS | `udp.dstport == 53` |
| Initial TCP SYN | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| SYN-ACK | `tcp.flags.syn == 1 && tcp.flags.ack == 1` |
| Reset | `tcp.flags.reset == 1` |
| FIN | `tcp.flags.fin == 1` |
| TCP payload present | `tcp.len > 0` |
| No TCP payload | `tcp.len == 0` |
| Retransmission | `tcp.analysis.retransmission` |
| Duplicate ACK | `tcp.analysis.duplicate_ack` |
| Fast retransmission | `tcp.analysis.fast_retransmission` |
| Any TCP analysis flag | `tcp.analysis.flags` |
| ARP request | `arp.opcode == 1` |
| ARP reply | `arp.opcode == 2` |
| Low IPv4 TTL | `ip.ttl < 10` |
| Exact IPv4 TTL | `ip.ttl == 64` |
| Ethernet broadcast | `eth.dst == ff:ff:ff:ff:ff:ff` |
| Suspicious MAC in either direction | `eth.addr == 66:66:66:66:66:66` |

Useful combinations:

```text
ip.src == 10.0.0.5 && tcp.flags.syn == 1 && tcp.flags.ack == 0
ip.dst == 10.0.0.20 && tcp.flags.syn == 1 && tcp.flags.ack == 0
tcp.port == 9000 && tcp.analysis.flags
arp.opcode == 2 && arp.src.proto_ipv4 == 192.168.1.1
```

## Capture filters

These are BPF expressions used before or during a live capture. Non-matching packets are not recorded.

| Goal | Capture filter |
| --- | --- |
| TCP only | `tcp` |
| UDP port 53 | `udp port 53` |
| One host | `host 10.10.10.25` |
| TCP port 80 | `tcp port 80` |

Do not paste capture-filter syntax into the display-filter bar. The two languages overlap in a few simple words, but they are not interchangeable.

