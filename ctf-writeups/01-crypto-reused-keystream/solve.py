"""Recover a message from two ciphertexts that reused an XOR keystream."""

import argparse
import json
import re
from pathlib import Path


def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("XOR inputs must have equal lengths")
    return bytes(a ^ b for a, b in zip(left, right))


def recover(challenge: dict) -> tuple[bytes, str]:
    known_plaintext = challenge["known_plaintext"].encode("ascii")
    known_ciphertext = bytes.fromhex(challenge["known_ciphertext_hex"])
    target_ciphertext = bytes.fromhex(challenge["target_ciphertext_hex"])
    if not target_ciphertext:
        raise ValueError("The target ciphertext is empty")
    keystream = xor_bytes(known_plaintext, known_ciphertext)
    if len(target_ciphertext) > len(keystream):
        raise ValueError("Known plaintext does not cover the whole target")
    plaintext = xor_bytes(target_ciphertext, keystream[:len(target_ciphertext)])
    flag = plaintext.decode("ascii")
    if not re.fullmatch(r"CTF\{[a-z0-9_]+\}", flag):
        raise ValueError("Recovered bytes do not match the expected flag format")
    return keystream, flag


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", type=Path,
                        default=Path(__file__).with_name("challenge.json"))
    args = parser.parse_args()
    challenge = json.loads(args.input.read_text(encoding="utf-8"))
    keystream, flag = recover(challenge)
    print(f"Recovered keystream: {len(keystream)} bytes")
    print(flag)


if __name__ == "__main__":
    main()
