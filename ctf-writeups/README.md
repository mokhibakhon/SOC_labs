# CTF Answers

Worked solutions to three CTF-style practice questions, with Python scripts, step-by-step explanations, and defensive takeaways.

| Question | Topic | Solution |
| --- | --- | --- |
| **Repeated Signals** | Recovering a message from a reused XOR keystream | [Read the solution](01-crypto-reused-keystream/README.md) |
| **Out of Order** | Reconstructing a message from fragmented HTTP logs | [Read the solution](02-forensics-fragmented-logs/README.md) |
| **Quoted Out** | Demonstrating and fixing a SQL injection flaw | [Read the solution](03-web-sql-injection/README.md) |

## Run the solutions

Use Python 3.10 or newer with the standard `sqlite3` module. No third-party Python packages are required. The recorded checks used Python 3.12.14.

From the `ctf-writeups` directory:

```bash
python3 01-crypto-reused-keystream/solve.py
python3 02-forensics-fragmented-logs/solve.py
python3 03-web-sql-injection/solve.py
python3 verify.py
```

On Windows, use `py -3` in place of `python3` if the Python launcher is installed.

## What's included

Each question has a write-up, its input data or local lab, and a working solver. The verification suite checks the recovered flags, incomplete or conflicting log fragments, and the parameterized SQL fix. See [the verification record](VERIFICATION.md) for results and fixture hashes.

The log entries and accounts are practice data. The SQL exercise runs in memory and does not start a web server.
