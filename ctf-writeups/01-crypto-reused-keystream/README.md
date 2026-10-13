# 01 · Repeated Signals

**Cryptography · Introductory · Original practice challenge**

[All write-ups](../README.md) · [Challenge data](challenge.json) · [Complete solver](solve.py)

## Challenge

Two messages were encrypted by XORing their bytes with the same keystream, starting at byte zero. The first message is a public weather report. Recover the second message, which has the form `CTF{...}`.

The supplied JSON contains the known plaintext and both ciphertexts in hexadecimal. The known message is 49 ASCII bytes; the target ciphertext is 41 bytes. This matters because the known message covers every keystream position needed to decrypt the target.

## Reasoning

For a plaintext byte sequence $P$ and a keystream $K$, XOR encryption produces:

$$C = P \oplus K$$

XORing a value with itself gives zero, so the known message exposes the corresponding keystream bytes:

$$K = C_1 \oplus P_1$$

The same bytes can then recover the target:

$$P_2 = C_2 \oplus K = C_2 \oplus C_1 \oplus P_1$$

All operations apply only to aligned, overlapping positions. Here, both messages start at position zero and the entire target is covered.

The first byte provides a useful manual check:

| Quantity | Hexadecimal value |
| --- | --- |
| Known plaintext byte `D` | `44` |
| Known ciphertext byte | `10` |
| Recovered keystream byte: `44 XOR 10` | `54` |
| Target ciphertext byte | `17` |
| Recovered target byte: `17 XOR 54` | `43` = `C` |

This is a known-plaintext recovery. Searching for a short repeating key or brute-forcing a password would add assumptions that the challenge does not require.

## Solution

Decode the hexadecimal strings into bytes, recover the keystream, then XOR its first 41 bytes with the target. The essential operation is:

```python
def xor_bytes(left, right):
    if len(left) != len(right):
        raise ValueError("XOR inputs must have equal lengths")
    return bytes(a ^ b for a, b in zip(left, right))

keystream = xor_bytes(known_plaintext, known_ciphertext)
plaintext = xor_bytes(target_ciphertext, keystream[:len(target_ciphertext)])
```

The complete solver also rejects insufficient known plaintext and checks that the recovered text matches the flag format. Explicit length checks prevent Python's `zip` from silently truncating an invalid pair.

From the `ctf-writeups` directory:

```bash
python3 01-crypto-reused-keystream/solve.py
```

Observed output:

```text
Recovered keystream: 49 bytes
CTF{reusing_a_keystream_reveals_messages}
```

## What the result establishes

The supplied known message decrypts the entire target under the stated reuse assumption. It reveals a segment of the keystream, not a master encryption key. With fewer known bytes, only the matching positions could be recovered by this method. If the target used an independent keystream, these equations would not recover it.

Matching `CTF{...}` is a useful format check, not a cryptographic integrity check. The regression tests check the exact expected flag and reject an uncovered target, a length mismatch, and a changed first byte of known plaintext.

## Defensive takeaway

Never reuse a one-time XOR pad. In a real application, use an established authenticated-encryption implementation and follow its nonce requirements. For ChaCha20-Poly1305, repeating a nonce under the same key repeats the keystream and creates this kind of exposure; authentication does not make nonce reuse safe. See [RFC 8439, section 4](https://www.rfc-editor.org/rfc/rfc8439.html#section-4).

This lab isolates the XOR mistake; it is not an implementation or a break of ChaCha20.
