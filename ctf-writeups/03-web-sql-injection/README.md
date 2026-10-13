# 03 · Quoted Out

**Web security / local backend · Introductory · Practice challenge**

[All write-ups](../README.md) · [Login implementation](lab.py) · [Complete solver](solve.py)

## Challenge

A small login function constructs a SQL statement from a username and password. Obtain the administrator flag through that function without knowing the administrator password, then fix the demonstrated flaw.

The exercise runs entirely in an in-memory SQLite database. It models backend login logic without starting an HTTP server. The administrator password is randomly generated for each database instance. All accounts are synthetic; plaintext password storage is a deliberate simplification for this exercise.

This is a source-visible lab. Reading the flag constant directly skips the learning objective: the solution must demonstrate the authentication bypass and then verify the fix.

## Find the trust-boundary mistake

The vulnerable function constructs this query with an f-string:

```python
query = (
    "SELECT username, role FROM users "
    f"WHERE username = '{username}' AND password = '{password}'"
)
```

An ordinary invalid password returns no account. But a quote in the username can end the SQL string literal. Input has become part of the statement's syntax.

Use the following values:

| Field | Value |
| --- | --- |
| Username | `admin' -- `, including the trailing space |
| Password | `wrong-password` |

The executed query becomes:

```sql
SELECT username, role FROM users
WHERE username = 'admin' -- ' AND password = 'wrong-password'
```

The quote closes `admin`; `--` starts a comment extending to the end of this query line. The password condition is therefore ignored, leaving a query for the administrator account.

A generic `OR 1=1` payload would not reliably select the administrator: multiple rows could match, and there is no `ORDER BY`. Targeting the known username makes the result specific.

## Reproduce the bypass

From the `ctf-writeups` directory:

```bash
python3 03-web-sql-injection/lab.py --username "admin' -- " --password wrong-password
```

Observed output:

```text
Authenticated: admin (role: admin)
CTF{parameters_keep_data_out_of_sql}
```

The complete solver also exercises the patched function in the same database instance:

```bash
python3 03-web-sql-injection/solve.py
```

Observed output:

```text
Payload username: "admin' -- "
Executed SQL: SELECT username, role FROM users WHERE username = 'admin' -- ' AND password = 'wrong-password'
Vulnerable login: admin
CTF{parameters_keep_data_out_of_sql}
Parameterized login: access denied
Legitimate guest login: succeeds
```

## Fix and verify

Define the SQL statement independently of the supplied values:

```python
connection.execute(
    "SELECT username, role FROM users WHERE username = ? AND password = ?",
    (username, password),
).fetchone()
```

The placeholders stay unquoted. SQLite receives the tuple values as data, so it searches for a username literally containing the payload instead of interpreting it as SQL syntax. Python documents this approach in [its parameter-binding guide](https://docs.python.org/3/library/sqlite3.html#how-to-use-placeholders-to-bind-values-in-sql-queries), and [OWASP recommends parameterized queries](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html#defense-option-1-prepared-statements-with-parameterized-queries).

Run the same payload against the fixed version:

```bash
python3 03-web-sql-injection/lab.py --fixed --username "admin' -- " --password wrong-password
```

Observed output:

```text
Access denied
```

The regression checks establish that the payload reaches `admin` before the fix and is rejected afterward. They also verify that valid guest credentials still work, invalid credentials fail, and the legitimate username `o'hara` works with parameter binding. Rejecting every apostrophe would break that valid account without addressing the underlying design properly.

## Defensive takeaway and scope

Keep SQL structure separate from user-controlled values. Parameter binding fixes this injection point; it does not by itself provide password hashing, rate limiting, secure sessions, or a complete authorization design. The patched function remains a teaching example rather than production login code.
