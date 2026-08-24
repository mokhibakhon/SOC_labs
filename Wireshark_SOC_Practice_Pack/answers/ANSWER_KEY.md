# Answer Key

Packet numbers below refer to the named capture. Wireshark may show relative rather than raw TCP sequence numbers, and TCP analysis wording can vary slightly by version.

## Lab 1

1. `01a` contains 15 packets.
2. `tcp` displays 11; `udp` displays 2; `arp` displays 2. Filtering hides non-matching packets but does not renumber the **No.** column, so gaps are expected.
3. Packet 5 is the first SYN without ACK: `10.10.10.25:51000 -> 10.10.10.50:80`. The sender, `10.10.10.25:51000`, initiated the connection.
4. The client is `10.10.10.25:51000`; the server is `10.10.10.50:80`. A reply reverses source and destination, so the client's temporary source port becomes the reply's destination port.
5. Packet 8 carries 52 bytes from client to server. Packet 10 carries 40 bytes from server to client.
6. The server sends FIN first in packet 12. The client acknowledges in packet 13 and closes its own direction separately with FIN in packet 14.
7. The stream contains `GET /status` with host `portal.training.test`, followed by `HTTP/1.1 200 OK` and body `OK`.
8. `01b` has only the 11 TCP packets. ARP and UDP are absent because the file simulates capture-time filtering; they were never recorded.

## Lab 2

1. The flows are `52000 -> 22`, `52001 -> 23`, `52002 -> 445`, and `52003 -> 8080`.
2. Port 22 is open enough to complete the handshake in packets 1-3. Port 8080 also completes a handshake in packets 15-17 before the application flow is reset.
3. Port 23 is probably closed: packet 10 SYN is answered by packet 11 RST-ACK.
4. Port 445 has three SYN attempts in packets 12-14 and no visible reply. Safest conclusion: no response is visible; filtering, packet loss, capture loss, an unreachable host/path, or a silent service policy remain possible.
5. Packet 4 is ACK-only at the flag level but has `tcp.len = 24`, sent from client to server.
6. Packet 6 is FIN-ACK with `tcp.len = 18`, sent from server to client. FIN consumes sequence space after the final data.
7. Packet 19 is the abrupt reset, sent by `192.168.56.20:8080` after the handshake and client command.
8. Packet 19 has `tcp.len = 18`. RST instructs the peer to abort, so accompanying bytes cannot be treated as a reliably delivered final application message.

## Lab 3

1. The port 9000 flow is packets 1-14. The port 9001 flow is packets 15-20.
2. Packets 8, 10, and 12 repeat the server ACK for the same next expected client sequence. They are the duplicate-ACK pattern.
3. Packet 13 repeats the same 100-byte sequence range first sent in packet 6. It follows three duplicate ACKs and is the fast-recovery retransmission.
4. Typical Wireshark output marks packets 8/10/12 as duplicate ACKs and packet 13 as a fast retransmission. Additional analysis flags can appear depending on preferences and version.
5. Packet 18 is the original 80-byte segment; packet 19 repeats it about 1.2 seconds later. Packet 20 finally acknowledges the range.
6. The original data could have been lost after the capture point, its ACK could have been lost, or the capture could be incomplete/delayed. A retransmission alone does not prove which event occurred.

## Lab 4

1. `10.0.0.5` performs a vertical scan of `10.0.0.20` on ports 21, 22, 23, 80, and 443.
2. Port 21: probably closed (packets 1-2). Port 22: probably open (3-5). Port 23: no visible response (6). Port 80: probably open (7-9). Port 443: probably closed (10-11).
3. `10.0.0.6` performs a horizontal scan of TCP 445 across `10.0.0.20` through `10.0.0.24` in packets 12-22.
4. `.20`: probably closed; `.21`: no visible response; `.22`: probably open; `.23`: probably closed; `.24`: probably open.
5. `10.0.0.7` changes both destination addresses and ports in packets 23-34. Describe it as broader network/service discovery rather than a purely horizontal or vertical scan.
6. Half-open triplets are packets 3-5, 7-9, 15-17, 20-22, 25-27, and 31-33. The scanner learns from SYN-ACK and sends RST instead of completing the handshake.
7. Silence does not distinguish filtering, drops, host/path failure, capture loss, or another policy. It is not the same evidence as RST-ACK.

## Lab 5

1. Packet 1 is a broadcast request from `192.168.1.10`: it asks for the MAC associated with `192.168.1.50`. Packet 2 answers `02:00:00:00:01:50`.
2. Packet 3 has IPv4 destination `192.168.1.50` and Ethernet destination `02:00:00:00:01:50`; the peer is local in the same `/24`.
3. Packet 5 broadcasts because the requester does not yet know the gateway MAC. Packet 6 can reply directly to the requester's known MAC.
4. Packet 7 keeps IPv4 destination `203.0.113.80`, but its Ethernet destination is gateway MAC `00:11:22:33:44:55`. The remote IP is the network destination; the gateway is the next local hop.
5. Gateway IP `192.168.1.1` is claimed by `00:11:22:33:44:55` in packets 6, 10, 16, and 20, and by `66:66:66:66:66:66` in packets 11, 17, and 21.
6. After the suspicious claim, packets 12 and 18 from the victim use Ethernet destination `66:66:66:66:66:66` while keeping the remote IPv4 destination.
7. Packets 12-13 carry the same outbound IP data across `victim -> suspicious MAC -> gateway`. Packets 14-15 carry the same inbound IP data across `gateway -> suspicious MAC -> victim`.
8. The evidence is consistent with ARP poisoning and forwarding through a possible man-in-the-middle. It is not conclusive by itself. Validate the MACs against router/switch/DHCP/asset records and check for legitimate redundancy or failover, duplicate-IP configuration, or a lab/virtual network appliance.

## Lab 6

1. For local peer `172.16.5.20`, packet 1 ARPs directly for that IP, packet 2 returns MAC `02:00:00:00:05:20`, and packet 3 uses that MAC.
2. For `172.16.6.20`, the host first resolves gateway `172.16.5.1` in packets 5-6. Packet 7 retains IPv4 destination `172.16.6.20` but uses gateway MAC `02:00:00:00:05:01`.
3. Under `/24`, the network portions are `172.16.5` and `172.16.6`, so they are different subnets even though both addresses are private.
4. Both `172.16.6.20` and public `198.51.100.25` are outside `172.16.5.0/24`, so packets 7 and 10 use the gateway MAC.
5. `ip.ttl < 10` matches packet 13 at TTL 2 and packet 15 at TTL 9.
6. Packet 14 is ICMP Time Exceeded from `172.16.5.1` after packet 13. It demonstrates that a router drops a packet when its TTL budget expires instead of forwarding it indefinitely.
7. If the starting TTL is known to be 64, observed TTL 58 suggests about 6 forwarding hops.
8. No exact hop count follows from 117 or 243 alone because the starting TTL is unknown. Guessing common starting values such as 128 or 255 is an inference, not proof.

## Lab 7

1. Packet 1 is the first SYN without ACK, so `127.0.0.1:55000` initiated the connection to `127.0.0.1:3000`.
2. Handshake: packets 1-3. Client payload: packet 4, 13 bytes. Server payload: packet 6, 14 bytes.
3. The client closes its sending direction first with FIN in packet 8. The server closes separately in packet 10.
4. This file uses the raw IPv4 PCAP link type to represent loopback. There is no Ethernet next hop and no ARP resolution. Real operating systems may label loopback captures with a different loopback link-layer type, but the reasoning is the same.
5. Both endpoints belong to the same host; the operating system delivers the traffic internally rather than placing it on the LAN.

## Lab 8

1. Protocols are DNS over UDP, TCP, HTTP, ARP, and ICMP. Key IPs include user `10.20.30.25`, internal server `10.20.30.40`, DNS server `10.20.30.53`, gateway `10.20.30.1`, suspicious host `10.20.30.77`, and remote service `203.0.113.50`.
2. Packet 1 queries `updates.training.test` from UDP source port 57000 to `10.20.30.53:53`. Packet 2 answers `10.20.30.40`.
3. HTTP is packets 3-13. `10.20.30.25:57001` initiates to `10.20.30.40:80`, requests `/health`, receives `200 OK` with body `healthy`, and the server sends FIN first before the client closes its direction.
4. TCP 3389 is actively rejected: packet 14 SYN is answered by packet 15 RST-ACK.
5. `10.20.30.77` vertically scans `10.20.30.40` on ports 21, 22, 23, 80, 443, and 445 in packets 16-27.
6. Open-looking: 22 and 80. Closed-looking: 21 and 443. No visible response: 23 and 445.
7. Half-open triplets are packets 18-20 for port 22 and 22-24 for port 80.
8. Packet 28 has IPv4 destination `203.0.113.50` and Ethernet destination gateway MAC `02:20:30:00:00:01`.
9. Packets 31/34 claim `10.20.30.1` is at `02:20:30:00:00:01`. Packets 32/35 claim the same IP is at `02:20:30:00:00:77`. Packet 33 then sends a remote-destination IP packet to Ethernet MAC `02:20:30:00:00:77`.
10. Packet 33 has ACK set, PSH clear, and `tcp.len = 14`, proving ACK does not mean no data.
11. Packet 39 is the original 64-byte segment. Packet 40 repeats the same sequence range about 1.2 seconds later; packet 41 acknowledges it.
12. Packet 42 is an ICMP echo request with TTL 2; packet 43 is ICMP Time Exceeded from the gateway.
13. Example incident note: "The capture shows `10.20.30.77` sending initial SYNs to six ports on `10.20.30.40`, including two SYN-ACK-to-RST half-open sequences. The same host's MAC also claims gateway IP `10.20.30.1`, after which one remote-destination frame from `10.20.30.25` is addressed to that MAC. Together, these facts are consistent with reconnaissance plus possible ARP poisoning, but they do not by themselves prove malicious ownership or interception. Legitimate failover, duplicate-IP configuration, or an authorized security test remain alternatives. Validate the MAC and IP against switch CAM, DHCP, router, asset, and change records, then correlate timing with endpoint and authentication logs."

