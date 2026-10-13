"""Demonstrate the login flaw and verify that parameter binding blocks it."""

from lab import create_database, get_flag, login_fixed, login_vulnerable, unsafe_query


def main() -> None:
    username = "admin' -- "
    password = "wrong-password"
    connection = create_database()
    try:
        before = login_vulnerable(connection, username, password)
        after = login_fixed(connection, username, password)
        ordinary = login_fixed(connection, "guest", "guest-demo-password")
        if before != ("admin", "admin"):
            raise RuntimeError("The demonstration did not reach the administrator")
        if after is not None or ordinary != ("guest", "user"):
            raise RuntimeError("The parameterized-query regression check failed")
        print(f"Payload username: {username!r}")
        print(f"Executed SQL: {unsafe_query(username, password)}")
        print(f"Vulnerable login: {before[0]}")
        print(get_flag(before))
        print("Parameterized login: access denied")
        print("Legitimate guest login: succeeds")
    finally:
        connection.close()


if __name__ == "__main__":
    main()
