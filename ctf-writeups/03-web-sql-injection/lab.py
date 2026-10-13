"""An intentionally vulnerable, in-memory login exercise. No HTTP server."""

import argparse
import secrets
import sqlite3


FLAG = "CTF{parameters_keep_data_out_of_sql}"


def create_database() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.execute(
        "CREATE TABLE users (username TEXT PRIMARY KEY, password TEXT, role TEXT)"
    )
    # All accounts are synthetic. Plaintext password storage is lab-only.
    # Guest is inserted first to make a generic OR 1=1 bypass insufficient
    # as a reliable way to select the administrator.
    connection.executemany(
        "INSERT INTO users VALUES (?, ?, ?)",
        [("guest", "guest-demo-password", "user"),
         ("admin", secrets.token_urlsafe(24), "admin"),
         ("o'hara", "library-demo-password", "user")],
    )
    return connection


def unsafe_query(username: str, password: str) -> str:
    return (
        "SELECT username, role FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )


def login_vulnerable(connection, username: str, password: str):
    return connection.execute(unsafe_query(username, password)).fetchone()


def login_fixed(connection, username: str, password: str):
    return connection.execute(
        "SELECT username, role FROM users WHERE username = ? AND password = ?",
        (username, password),
    ).fetchone()


def get_flag(account) -> str | None:
    if account == ("admin", "admin"):
        return FLAG
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--fixed", action="store_true")
    args = parser.parse_args()
    connection = create_database()
    try:
        login = login_fixed if args.fixed else login_vulnerable
        account = login(connection, args.username, args.password)
        if account is None:
            print("Access denied")
        else:
            print(f"Authenticated: {account[0]} (role: {account[1]})")
            print(get_flag(account) or "No administrator flag for this account")
    except sqlite3.OperationalError as exc:
        print(f"SQL error: {exc}")
    finally:
        connection.close()


if __name__ == "__main__":
    main()
