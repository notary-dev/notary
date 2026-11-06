"""Pruebas del contador local de PIN incorrectos (no se puede consultar a la tarjeta)."""

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from hashlib import sha256
from pathlib import Path
from unittest import mock

import PyKCS11

from notary import cli
from notary.pin_guard import MAX_FAILED_BEFORE_REFUSAL, PinGuard
from notary.signer.pkcs11_signer import PKCS11Signer
from tests.test_cli_and_pkcs11 import Pkcs11SignerTests, _SimulatedP11Lib

SERIAL = "020404b70b140d"


class PinGuardTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "estado" / "pin_guard.json"
        self.guard = PinGuard(self.path)

    def tearDown(self):
        self._tmp.cleanup()

    def test_refuses_after_the_maximum_number_of_failures(self):
        self.guard.check_allowed(SERIAL)
        for _ in range(MAX_FAILED_BEFORE_REFUSAL):
            self.guard.record_failure(SERIAL)
        with self.assertRaisesRegex(RuntimeError, "PAD"):
            self.guard.check_allowed(SERIAL)

    def test_one_failure_is_still_allowed(self):
        self.guard.record_failure(SERIAL)
        self.guard.check_allowed(SERIAL)
        self.assertEqual(self.guard.failed_attempts(SERIAL), 1)

    def test_success_resets_the_counter(self):
        self.guard.record_failure(SERIAL)
        self.guard.record_success(SERIAL)
        self.assertEqual(self.guard.failed_attempts(SERIAL), 0)

    def test_counters_are_per_card(self):
        self.guard.set_failed(SERIAL, 2)
        self.assertEqual(self.guard.failed_attempts("OTRA-TARJETA"), 0)

    def test_serial_number_is_not_stored_in_clear(self):
        self.guard.set_failed(SERIAL, 1)
        self.assertNotIn(SERIAL, self.path.read_text(encoding="utf-8"))

    def test_unreadable_state_refuses_instead_of_assuming_zero(self):
        self.path.parent.mkdir(parents=True)
        self.path.write_text("esto no es json", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "no se puede leer"):
            self.guard.check_allowed(SERIAL)


class SignerGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Pkcs11SignerTests.setUpClass()
        cls.helper = Pkcs11SignerTests("test_digest_info_requires_32_byte_sha256")

    @classmethod
    def tearDownClass(cls):
        Pkcs11SignerTests.tearDownClass()

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.guard = PinGuard(Path(self._tmp.name) / "pin_guard.json")
        self.pin_calls = []

    def tearDown(self):
        self._tmp.cleanup()

    def _signer(self, session):
        p11 = _SimulatedP11Lib(flags=0, session=session)
        return PKCS11Signer(
            module_path=str(Pkcs11SignerTests.fake_module),
            pin_provider=lambda: (self.pin_calls.append(1) or "0000"),
            p11_factory=lambda: p11,
            guard=self.guard,
        )

    def test_third_pin_is_not_even_requested_after_two_wrong_ones(self):
        session = self.helper._make_session(login_error=PyKCS11.PyKCS11Error(0xA0))
        signer = self._signer(session)
        digest = sha256(b"datos").digest()
        for expected in (1, 2):
            with self.assertRaisesRegex(RuntimeError, f"registrados: {expected} de 3"):
                signer.sign_hash(digest)
        with self.assertRaisesRegex(RuntimeError, "PAD"):
            signer.sign_hash(digest)
        # El tercer intento se corta antes de pedir el PIN y antes de tocar la tarjeta.
        self.assertEqual(len(self.pin_calls), 2)
        self.assertEqual(session.login_attempts, 2)

    def test_a_correct_pin_resets_the_counter(self):
        self.guard.set_failed(SERIAL_TEST_TOKEN, 1)
        signer = self._signer(self.helper._make_session())
        signer.sign_hash(sha256(b"datos").digest())
        self.assertEqual(self.guard.failed_attempts(SERIAL_TEST_TOKEN), 0)

    def test_a_locked_pin_marks_the_card_as_exhausted(self):
        session = self.helper._make_session(login_error=PyKCS11.PyKCS11Error(PyKCS11.CKR_PIN_LOCKED))
        signer = self._signer(session)
        with self.assertRaises(RuntimeError):
            signer.sign_hash(sha256(b"datos").digest())
        self.assertEqual(self.guard.failed_attempts(SERIAL_TEST_TOKEN), 3)

    def test_other_card_errors_do_not_count_as_wrong_pin(self):
        session = self.helper._make_session(login_error=PyKCS11.PyKCS11Error(PyKCS11.CKR_DEVICE_ERROR))
        signer = self._signer(session)
        with self.assertRaises(RuntimeError):
            signer.sign_hash(sha256(b"datos").digest())
        self.assertEqual(self.guard.failed_attempts(SERIAL_TEST_TOKEN), 0)


SERIAL_TEST_TOKEN = "TOKEN-DE-PRUEBA"


class PinGuardCommandTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.state = Path(self._tmp.name) / "estado"
        self._patches = [
            mock.patch.dict("os.environ", {"NOTARY_STATE_DIR": str(self.state)}),
            mock.patch("notary.pin_guard.find_pkcs11_module", return_value="modulo"),
            mock.patch(
                "notary.pin_guard.PyKCS11.PyKCS11Lib",
                lambda: _SimulatedP11Lib(flags=0, session=None),
            ),
        ]
        for patcher in self._patches:
            patcher.start()

    def tearDown(self):
        for patcher in self._patches:
            patcher.stop()
        self._tmp.cleanup()

    def _run(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(["pin-guard", *argv])
        return code, out.getvalue(), err.getvalue()

    def test_set_show_and_reset(self):
        code, stdout, _ = self._run("--set", "2")
        self.assertEqual(code, 0)
        self.assertIn("2 de 3", stdout)
        self.assertIn("se niega", stdout)
        code, stdout, _ = self._run()
        self.assertIn("2 de 3", stdout)
        code, stdout, _ = self._run("--reset")
        self.assertEqual(code, 0)
        self.assertIn("0 de 3", stdout)

    def test_invalid_arguments_are_rejected(self):
        self.assertEqual(self._run("--reset", "--set", "1")[0], 2)
        self.assertEqual(self._run("--set", "9")[0], 2)


if __name__ == "__main__":
    unittest.main()
