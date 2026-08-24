# Wireshark SOC Foundations Practice Pack

This pack turns the attached revision notes into hands-on packet analysis. It contains 9 synthetic PCAP files with 191 packets total, a guided worksheet, a filter sheet, and a separate answer key.

## Recommended order

1. Open `PRACTICE_GUIDE.md`.
2. Work through captures `01a` to `07` in order.
3. Analyze `08_mixed_soc_challenge.pcap` without opening the answer key.
4. Check your reasoning in `answers/ANSWER_KEY.md`.

## Open a capture

1. Extract this ZIP.
2. In Wireshark, choose **File > Open** and select a file from `captures/`.
3. Enter display filters in the filter bar at the top.
4. Select a packet and expand **Ethernet II**, **Internet Protocol Version 4**, and **Transmission Control Protocol** in the packet details pane.
5. For an application conversation, right-click a TCP packet and choose **Follow > TCP Stream**.

Wireshark normally displays relative TCP sequence numbers. That is fine; packet numbers, directions, flags, acknowledgements, and payload lengths are the important evidence in these exercises.

## Important limitation

A saved PCAP can practice display filters directly, but a real capture filter acts before packets are saved. Files `01a` and `01b` demonstrate the difference: `01a` is the complete capture, while `01b` simulates a capture made with the BPF capture filter `tcp`. The ARP and UDP packets were never saved in `01b`, so no display filter can bring them back.

## Safety and scope

All traffic is synthetic and offline. The captures use private IP ranges, loopback, and documentation-only public ranges. They contain no real credentials, malware, or live scanning traffic.

