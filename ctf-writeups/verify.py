"""Run reproducibility and regression checks with the Python standard library."""

import binascii
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def load_module(name, relative_path):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


crypto = load_module("crypto_solver", "01-crypto-reused-keystream/solve.py")
forensics = load_module("log_solver", "02-forensics-fragmented-logs/solve.py")
lab = load_module("login_lab", "03-web-sql-injection/lab.py")


class CryptoChecks(unittest.TestCase):
    def setUp(self):
        self.challenge = json.loads(
            (ROOT / "01-crypto-reused-keystream/challenge.json").read_text()
        )

    def test_recover_expected_flag(self):
        key, flag = crypto.recover(self.challenge)
        self.assertEqual(len(key), 49)
        self.assertEqual(flag, "CTF{reusing_a_keystream_reveals_messages}")

    def test_reject_mismatched_known_pair(self):
        self.challenge["known_ciphertext_hex"] += "00"
        with self.assertRaisesRegex(ValueError, "equal lengths"):
            crypto.recover(self.challenge)

    def test_reject_uncovered_target(self):
        self.challenge["target_ciphertext_hex"] += "00" * 9
        with self.assertRaisesRegex(ValueError, "cover the whole target"):
            crypto.recover(self.challenge)

    def test_wrong_known_plaintext_breaks_flag(self):
        # Alter a byte in the flag-prefix region; format validation catches it.
        self.challenge["known_plaintext"] = "E" + self.challenge["known_plaintext"][1:]
        with self.assertRaisesRegex(ValueError, "expected flag format"):
            crypto.recover(self.challenge)


class ForensicsChecks(unittest.TestCase):
    def setUp(self):
        self.lines = (ROOT / "02-forensics-fragmented-logs/access.log").read_text().splitlines()

    def test_recover_and_deduplicate(self):
        self.assertEqual(
            forensics.recover(self.lines),
            ("CTF{follow_the_sequence_not_the_timestamps}", 12, 1),
        )

    def test_file_order_does_not_change_reassembly(self):
        self.assertEqual(forensics.recover(reversed(self.lines)), forensics.recover(self.lines))

    def test_missing_fragment_is_an_error(self):
        lines = [line for line in self.lines if "seq=12&" not in line]
        with self.assertRaisesRegex(ValueError, r"Missing fragments: \[12\]"):
            forensics.recover(lines)

    def test_conflicting_retry_is_an_error(self):
        line = next(line for line in self.lines if "seq=3&" in line)
        altered = line.replace("data=xvd19", "data=AAAAA")
        with self.assertRaisesRegex(ValueError, "Conflicting duplicate fragment: 3"):
            forensics.recover(self.lines + [altered])

    def test_non_base64_data_is_rejected(self):
        lines = [line.replace("data=Q1RGe", "data=%21%21%21%21%21") for line in self.lines]
        with self.assertRaises(binascii.Error):
            forensics.recover(lines)

    def test_repeated_query_field_is_rejected(self):
        lines = [line.replace("seq=1&", "seq=1&seq=1&") for line in self.lines]
        with self.assertRaisesRegex(ValueError, "Missing or repeated transfer fields"):
            forensics.recover(lines)


class LoginChecks(unittest.TestCase):
    def setUp(self):
        self.connection = lab.create_database()

    def tearDown(self):
        self.connection.close()

    def test_payload_bypasses_vulnerable_login(self):
        account = lab.login_vulnerable(self.connection, "admin' -- ", "wrong-password")
        self.assertEqual(account, ("admin", "admin"))
        self.assertEqual(lab.get_flag(account), "CTF{parameters_keep_data_out_of_sql}")

    def test_parameter_binding_rejects_payloads(self):
        for username in ("admin' -- ", "' OR 1=1 -- ", "admin' OR '1'='1"):
            with self.subTest(username=username):
                self.assertIsNone(lab.login_fixed(self.connection, username, "wrong-password"))

    def test_valid_and_invalid_ordinary_credentials(self):
        for login in (lab.login_vulnerable, lab.login_fixed):
            with self.subTest(login=login.__name__):
                guest = login(self.connection, "guest", "guest-demo-password")
                self.assertEqual(guest, ("guest", "user"))
                self.assertIsNone(lab.get_flag(guest))
                self.assertIsNone(login(self.connection, "guest", "wrong-password"))

    def test_fixed_login_accepts_apostrophe_in_real_username(self):
        self.assertEqual(
            lab.login_fixed(self.connection, "o'hara", "library-demo-password"),
            ("o'hara", "user"),
        )


class CommandLineChecks(unittest.TestCase):
    def test_solvers_run_outside_the_repository(self):
        cases = [
            ("01-crypto-reused-keystream", "CTF{reusing_a_keystream_reveals_messages}"),
            ("02-forensics-fragmented-logs", "CTF{follow_the_sequence_not_the_timestamps}"),
            ("03-web-sql-injection", "CTF{parameters_keep_data_out_of_sql}"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            for folder, flag in cases:
                with self.subTest(folder=folder):
                    result = subprocess.run(
                        [sys.executable, str(ROOT / folder / "solve.py")],
                        cwd=directory, capture_output=True, text=True, check=True,
                    )
                    self.assertIn(flag, result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
