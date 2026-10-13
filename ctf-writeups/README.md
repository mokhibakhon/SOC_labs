# CTF Lab Notes

Three small security problems, explained from the first clue to a working solution and a defensive takeaway.

These are **original, AI-assisted practice labs**. The challenge fixtures, initial solution code, and write-ups were created with ChatGPT assistance and verified in a Python environment. They are educational examples, not records of participation in a named competition. All log entries, accounts, and flags are synthetic.

## The write-ups

| # | Challenge | Area | Central question | Write-up |
| --- | --- | --- | --- | --- |
| 01 | **Repeated Signals** | Cryptography | What does known plaintext reveal when a keystream is reused? | [Read](01-crypto-reused-keystream/README.md) |
| 02 | **Out of Order** | Log forensics | How can a fragmented message be reconstructed despite retries and noise? | [Read](02-forensics-fragmented-logs/README.md) |
| 03 | **Quoted Out** | Web security / local backend | How does input become SQL code, and how can parameter binding stop it? | [Read](03-web-sql-injection/README.md) |

Each write-up includes the starting evidence, reasoning, executable solution, observed output, limitations, and a defensive lesson. The exercises are introductory; they emphasize clear reasoning and verification.

## Run everything

Use **Python 3.10 or newer** with the standard `sqlite3` module. No third-party Python packages, API keys, accounts, or network services are needed to run the labs. The recorded verification used Python 3.12.14; other versions have not been tested here.

From the root of this GitHub repository:

```bash
cd ctf-writeups
python3 01-crypto-reused-keystream/solve.py
python3 02-forensics-fragmented-logs/solve.py
python3 03-web-sql-injection/solve.py
python3 verify.py
```

On Windows, `py -3` can be used in place of `python3` when the Python launcher is installed.

The last command checks the expected flags, malformed or incomplete inputs, and the SQL fix. See [the verification record](VERIFICATION.md) for the environment, fixture hashes, and observed results.

## Explore the challenges first

To practice before reading the solutions, start with:

- [The two ciphertexts and known plaintext](01-crypto-reused-keystream/challenge.json).
- [The synthetic access log](02-forensics-fragmented-logs/access.log), looking for transfer `bluebird`.
- [The local login implementation](03-web-sql-injection/lab.py), with the goal of obtaining the administrator flag through the login function.

The SQL exercise deliberately contains a vulnerability and uses an in-memory database. It does not start a web server. Its parameterized version fixes the demonstrated injection; the simplified account model is not a production authentication system.

## Skills covered

- Translate an encryption property into a byte-level recovery algorithm.
- Parse evidence, filter irrelevant records, and validate a reconstruction.
- Explain an injection vulnerability and verify the behavior of a targeted fix.
- Write small Python tools with reproducible inputs and explicit failure cases.

## Extend the work

Useful next steps are to recover only a partial message when less plaintext is known, add a second interleaved transfer to the log exercise, or write a regression case for an additional SQL input. Personal reflections and independent extensions should describe work actually completed.
