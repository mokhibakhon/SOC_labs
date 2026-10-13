"""Reassemble a synthetic transfer from HTTP access-log fragments."""

import argparse
import base64
import re
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


# Deliberately scoped to the combined-log format shipped with this exercise.
REQUEST = re.compile(r'"GET ([^ ]+) HTTP/1\.[01]" (\d{3}) ')
FLAG = re.compile(r"CTF\{[a-z0-9_]+\}")


def recover(lines, transfer: str = "bluebird") -> tuple[str, int, int]:
    parts: dict[int, str] = {}
    total = None
    duplicates = 0

    for line in lines:
        match = REQUEST.search(line)
        if not match or match.group(2) != "200":
            continue
        url = urlsplit(match.group(1))
        if url.path != "/collect":
            continue
        query = parse_qs(url.query, keep_blank_values=True)
        if query.get("transfer") != [transfer]:
            continue
        if any(len(query.get(key, [])) != 1 for key in ("seq", "total", "data")):
            raise ValueError("Missing or repeated transfer fields")
        seq = int(query["seq"][0])
        advertised_total = int(query["total"][0])
        if not 1 <= advertised_total <= 1000 or not 1 <= seq <= advertised_total:
            raise ValueError("Invalid fragment sequence or total")
        if total is None:
            total = advertised_total
        elif total != advertised_total:
            raise ValueError("Conflicting fragment totals")
        data = query["data"][0]
        if seq in parts:
            if parts[seq] != data:
                raise ValueError(f"Conflicting duplicate fragment: {seq}")
            duplicates += 1
        else:
            parts[seq] = data

    if total is None:
        raise ValueError("No successful requests found for this transfer")
    missing = sorted(set(range(1, total + 1)) - parts.keys())
    if missing:
        raise ValueError(f"Missing fragments: {missing}")
    encoded = "".join(parts[seq] for seq in range(1, total + 1))
    flag = base64.b64decode(encoded, validate=True).decode("ascii")
    if not FLAG.fullmatch(flag):
        raise ValueError("Decoded transfer does not match the flag format")
    return flag, len(parts), duplicates


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", type=Path,
                        default=Path(__file__).with_name("access.log"))
    parser.add_argument("--transfer", default="bluebird")
    args = parser.parse_args()
    lines = args.input.read_text(encoding="utf-8").splitlines()
    flag, count, duplicates = recover(lines, args.transfer)
    print(f"Transfer: {args.transfer}")
    print(f"Unique fragments: {count}")
    print(f"Duplicate retries ignored: {duplicates}")
    print(flag)


if __name__ == "__main__":
    main()
