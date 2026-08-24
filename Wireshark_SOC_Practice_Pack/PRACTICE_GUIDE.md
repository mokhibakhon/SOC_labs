# Practice Guide

Record each answer before checking `answers/ANSWER_KEY.md`. State what the packets prove, then separate that from what they only suggest.

## Lab 1 - Direction, ports, protocols, and filters

Files:

- `01a_direction_ports_and_display_filters.pcap`
- `01b_tcp_capture_filter_simulation.pcap`

Tasks:

1. In `01a`, record the **Packets** total with no display filter.
2. Apply `tcp`, `udp`, and `arp` separately. Record the **Displayed** count for each and explain why the packet numbers have gaps.
3. Find the first SYN without ACK. Which IP and port initiated the TCP connection?
4. Identify the client endpoint and server endpoint. Why does port 51000 become the destination port in the reply?
5. Use `tcp.len > 0`. How many TCP packets carry payload, who sends each one, and how many bytes does each carry?
6. Which side sends FIN first? Does the other direction close immediately?
7. Follow the TCP stream. What request and response are visible?
8. Open `01b`. What protocols are permanently absent, and why can a display filter not restore them?

## Lab 2 - TCP outcomes, ACK payload, FIN, and RST

File: `02_tcp_outcomes_payload_and_closure.pcap`

Tasks:

1. List every client source port and corresponding server destination port.
2. Which destination port is shown as probably open by a completed handshake?
3. Which destination port is actively rejected with RST-ACK?
4. Which destination port receives repeated SYNs but no visible reply? Give the safest conclusion.
5. Find an ACK packet that carries data even though PSH is not set. Record direction and `tcp.len`.
6. Find a FIN-ACK that also carries final data. Record direction and `tcp.len`.
7. Find the abrupt reset after an established handshake. Which side sends it?
8. Does the reset carry payload? Explain why it should not be described as a reliably delivered final message.

## Lab 3 - Retransmission, duplicate ACKs, and fast recovery

File: `03_retransmission_duplicate_acks_and_fast_recovery.pcap`

Tasks:

1. Separate the two TCP connections by port or **Statistics > Conversations > TCP**.
2. In the port 9000 flow, identify the three repeated ACKs with the same acknowledgement number.
3. Which data segment is then sent again? Compare its sequence number and length with the earlier copy.
4. Apply `tcp.analysis.fast_retransmission`, `tcp.analysis.duplicate_ack`, and `tcp.analysis.flags`.
5. In the port 9001 flow, identify the original 80-byte segment and its later copy. Measure the time gap.
6. Explain three possible reasons a retransmission can appear without claiming that the receiver definitely missed the original.

Wireshark computes TCP analysis labels heuristically. A version may add labels such as out-of-order or spurious retransmission. The repeated sequence ranges and ACK evidence remain the primary facts.

## Lab 4 - Vertical, horizontal, broader, and half-open scans

File: `04_vertical_horizontal_and_half_open_scans.pcap`

Start with:

```text
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

Tasks:

1. Which source scans many ports on one destination host? Name the pattern and list the ports.
2. For that target, classify each port as probably open, probably closed, or no visible response.
3. Which source checks the same destination port across several hosts? Name the pattern and list the hosts.
4. For that horizontal pattern, classify each host response.
5. Which source changes both destination IPs and destination ports? What is the safer description of that activity?
6. Find every `SYN -> SYN-ACK -> RST` triplet. Why is that a strong half-open scan clue?
7. Why does a SYN with no response not prove a closed port?

## Lab 5 - Ethernet, ARP, gateway delivery, and spoofing evidence

File: `05_ethernet_arp_gateway_and_spoofing.pcap`

Tasks:

1. Find the ARP request for `192.168.1.50`. Who asks, and which MAC is requested?
2. Compare the Ethernet and IPv4 destinations of the local TCP SYN to `192.168.1.50`.
3. Find the ARP request for `192.168.1.1`. Why is the request broadcast while the normal reply is unicast?
4. Inspect the TCP SYN to `203.0.113.80`. What is its IPv4 destination? What is its Ethernet destination? Explain why they differ.
5. Filter ARP replies. Which two MAC addresses claim to own `192.168.1.1`?
6. After the conflicting claim, where does the victim send Ethernet frames for the remote IP?
7. Identify the two pairs of near-duplicate IP packets that show a possible forwarding path through the suspicious MAC.
8. Write a cautious SOC conclusion. Include at least two legitimate or non-malicious alternatives that must be checked.

## Lab 6 - Subnets, default gateway choices, and TTL

File: `06_subnets_gateway_choices_and_ttl.pcap`

Assume `172.16.5.10/24` is the local host.

Tasks:

1. For `172.16.5.20`, which IP is resolved with ARP and which destination MAC is used for the TCP SYN?
2. For `172.16.6.20`, which IP is resolved with ARP and which destination MAC is used? Why?
3. Both addresses begin with private `172.16`, so why are they not local to each other under `/24`?
4. Compare the path choice for `172.16.6.20` and `198.51.100.25`.
5. Apply `ip.ttl < 10`. Which packets match, and what TTL values do they have?
6. What response follows the packet with TTL 2? What does that demonstrate?
7. If a packet is known to have started at TTL 64 and is observed at 58, estimate the router count.
8. Can you calculate an exact hop count from observed TTL values 117 or 243 without knowing their starting TTLs? Explain.

## Lab 7 - Loopback and localhost

File: `07_loopback_localhost_raw_ipv4.pcap`

Tasks:

1. Which endpoint initiated the connection: `127.0.0.1:55000` or `127.0.0.1:3000`?
2. Identify the three-way handshake and the two payload directions.
3. Which side closes its sending direction first?
4. Why are there no ARP packets or Ethernet MAC addresses in this capture?
5. Explain why `127.0.0.1` traffic does not need to reach the LAN.

## Lab 8 - Mixed SOC challenge

File: `08_mixed_soc_challenge.pcap`

Do this lab without hints from the answer key.

1. Inventory the protocols and key endpoints.
2. Identify the DNS query, queried name, answer, client source port, and DNS server.
3. Identify the normal HTTP conversation. Who initiated it, what resource was requested, what was returned, and how did it close?
4. Identify an actively rejected service and state the evidence.
5. Identify the scanning source, target, scan type, and destination ports.
6. Classify the scanned ports by observed outcome.
7. Identify every half-open triplet in the scan.
8. For the connection to `203.0.113.50`, compare the IPv4 and Ethernet destinations.
9. Identify the conflicting ARP claims and the packet whose Ethernet destination changes afterward.
10. Find a TCP packet with ACK set, PSH not set, and `tcp.len > 0`.
11. Identify the original segment and ordinary retransmission in the port 9001 flow.
12. Find the low-TTL event and its response.
13. Write a five-sentence incident note that clearly separates facts, inferences, alternative explanations, and recommended validation steps.

