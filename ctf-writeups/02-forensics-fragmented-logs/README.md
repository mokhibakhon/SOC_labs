# 02 · Out of Order

**Log forensics · Introductory · Practice challenge**

[All write-ups](../README.md) · [Access log](access.log) · [Complete solver](solve.py)

## Challenge

A synthetic access log contains a message split across requests to `/collect`. Recover the message associated with transfer `bluebird`.

For this exercise, only requests with HTTP status `200` contribute fragments. The `seq` field gives a fragment's position, `total` gives the expected fragment count, and `data` holds part of one Base64 string. The log also contains unrelated traffic, a failed request, another transfer, and a retry.

The file has 18 entries. All addresses and timestamps are fictional fixture data.

## Inspect the evidence

The request targets expose the reassembly fields. For example:

```text
/collect?transfer=bluebird&seq=8&total=12&data=0X3Ro
/collect?transfer=bluebird&seq=12&total=12&data=zfQ%3D%3D
```

The second example includes percent-encoded padding: `%3D` represents `=`. URL query parsing must happen before Base64 decoding.

The successful unique fragments appear in this file order:

```text
8, 3, 11, 1, 6, 12, 2, 9, 5, 10, 4, 7
```

That order reflects logged requests, not the message's intended sequence. Sequence 3 is retried with identical data. A failed request advertises incorrect data for sequence 5, while transfer `canary` carries an unrelated heartbeat.

## Reconstruction

The solver follows five steps:

1. Extract `GET` requests with status `200` and path `/collect`.
2. Parse the query string and select `transfer=bluebird`.
3. Convert sequence numbers to integers and validate their range and total.
4. Deduplicate identical retries and require every sequence from 1 through 12.
5. Join the fragments in numeric order, then decode the complete Base64 value.

Selected fragments after ordering:

| Sequence | Data after URL decoding |
| --- | --- |
| 1 | `Q1RGe` |
| 2 | `2ZvbG` |
| 3 | `xvd19` |
| 10 | `W1lc3` |
| 11 | `RhbXB` |
| 12 | `zfQ==` |

The resulting string is:

```text
Q1RGe2ZvbGxvd190aGVfc2VxdWVuY2Vfbm90X3RoZV90aW1lc3RhbXBzfQ==
```

The final operation is small once the evidence is validated:

```python
encoded = "".join(parts[seq] for seq in range(1, total + 1))
flag = base64.b64decode(encoded, validate=True).decode("ascii")
```

`validate=True` rejects characters outside the Base64 alphabet instead of silently dropping them. This behavior is documented in [Python's Base64 reference](https://docs.python.org/3/library/base64.html#base64.b64decode).

From the `ctf-writeups` directory:

```bash
python3 02-forensics-fragmented-logs/solve.py
```

Observed output:

```text
Transfer: bluebird
Unique fragments: 12
Duplicate retries ignored: 1
CTF{follow_the_sequence_not_the_timestamps}
```

## Pitfalls and validation

Sorting sequence numbers as strings would place `10` before `2`. Sorting by timestamps would preserve request arrival order. Decoding each five-character fragment separately would fail because fragment boundaries do not align with Base64 blocks.

A retry is harmless only when its data matches the existing fragment. The solver reports conflicting duplicates and missing fragments instead of guessing. Regression checks also reverse the entire file, corrupt encoded data, and introduce an ambiguous query field.

The parser is intentionally scoped to this fixture's combined-log format. It is not a general-purpose parser for every proxy or web server. HTTP `200` is a rule of this challenge; in an investigation, that status alone would not prove that data was stored or that a request was malicious.

## Defensive takeaway

Encoded query fields can carry readable data once the encoding is reversed. Base64 provides no secrecy. A useful investigation correlates repeated endpoints, transfer identifiers, payload lengths, timing, and host context. Encoded-looking text alone is not enough to identify an incident or an actor.
