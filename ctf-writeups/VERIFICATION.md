# Verification record

The bundled exercises and scripts were checked on **2026-10-13** in the environment below.

## Environment

| Component | Version / value |
| --- | --- |
| Python | 3.12.14 |
| SQLite | 3.53.1 |
| Operating system | Linux |
| Third-party Python packages | None required |

## Results

`python3 verify.py` completed successfully: **15 tests passed**.

| Area | Checks |
| --- | --- |
| Cryptography | Exact recovered flag; mismatched known-pair lengths; insufficient keystream coverage; incorrect known plaintext in the flag prefix |
| Log forensics | Exact flag and retry count; reversed file order; missing fragment; conflicting retry; invalid Base64; repeated query field |
| SQL injection | Demonstrated administrator bypass; rejection of three payloads after parameter binding; valid and invalid ordinary credentials; legitimate apostrophe in a username |
| Command-line use | All three solvers executed successfully from a working directory outside the repository |

Each of the five output blocks associated with executable commands in the individual write-ups was also compared with the actual program output. All matched.

These are focused fixture and regression checks, not an exhaustive security audit. Only the environment above was used; compatibility with other Python versions is not established by this record.

## Fixture fingerprints

SHA-256 hashes identify the exact challenge artifacts used in this verification.

| File | SHA-256 |
| --- | --- |
| `01-crypto-reused-keystream/challenge.json` | `5aac753c74a3fa28a79500b68da722d26a2eb303193153fd2d910a199dd5bd32` |
| `02-forensics-fragmented-logs/access.log` | `d6143c0747f1197fc8f6ae50f83438a881d787b523bdab6b5ae2df76f987a046` |
| `03-web-sql-injection/lab.py` | `b2b60fccb5058d3589406bd03b2655e6de783f6167fde96fd76e3add3bc2ee24` |

## Reproduce

From the `ctf-writeups` directory:

```bash
python3 verify.py
```

The suite prints each check and ends with `OK` if all checks succeed. Execution time can vary by machine.
